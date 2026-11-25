//! Blob storage: content-addressed files on local disk or in any
//! S3-compatible bucket. Keys are node-go's (`blobs/<aa>/<sha256>`), so a
//! node-go data directory or bucket is used as it is.

use std::sync::Arc;

use bytes::Bytes;
use object_store::{ObjectStore, PutPayload, path::Path as ObjPath};

#[derive(Clone)]
pub struct Store {
    inner: Arc<dyn ObjectStore>,
    prefix: String,
}

pub fn blob_key(sha: &str) -> String {
    format!("blobs/{}/{}", &sha[..2.min(sha.len())], sha)
}

impl Store {
    pub fn open(url: &str, key_id: Option<&str>, secret: Option<&str>) -> Result<Store, String> {
        if let Some(path) = url.strip_prefix("file://") {
            std::fs::create_dir_all(path).map_err(|e| format!("OBX_BLOB_URL {path}: {e}"))?;
            let fs = object_store::local::LocalFileSystem::new_with_prefix(path)
                .map_err(|e| e.to_string())?;
            return Ok(Store {
                inner: Arc::new(fs),
                prefix: String::new(),
            });
        }
        let u = url::Url::parse(url).map_err(|e| format!("OBX_BLOB_URL: {e}"))?;
        let bucket = u
            .host_str()
            .ok_or("OBX_BLOB_URL needs a bucket name")?
            .to_string();
        let mut b = object_store::aws::AmazonS3Builder::from_env().with_bucket_name(&bucket);
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        b = b.with_region(q.get("region").cloned().unwrap_or_else(|| "auto".into()));
        if let Some(ep) = q.get("endpoint") {
            b = b
                .with_endpoint(ep)
                .with_allow_http(ep.starts_with("http://"));
        }
        if q.get("path_style").map(|v| v == "true").unwrap_or(false) {
            b = b.with_virtual_hosted_style_request(false);
        }
        if let (Some(k), Some(s)) = (key_id, secret) {
            b = b.with_access_key_id(k).with_secret_access_key(s);
        }
        let s3 = b.build().map_err(|e| format!("OBX_BLOB_URL: {e}"))?;
        let prefix = u.path().trim_matches('/').to_string();
        Ok(Store {
            inner: Arc::new(s3),
            prefix,
        })
    }

    fn path(&self, key: &str) -> ObjPath {
        if self.prefix.is_empty() {
            ObjPath::from(key)
        } else {
            ObjPath::from(format!("{}/{key}", self.prefix))
        }
    }

    pub async fn put(&self, key: &str, data: Bytes) -> Result<(), String> {
        self.inner
            .put(&self.path(key), PutPayload::from_bytes(data))
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub async fn get(&self, key: &str) -> Result<Option<Bytes>, String> {
        match self.inner.get(&self.path(key)).await {
            Ok(r) => r.bytes().await.map(Some).map_err(|e| e.to_string()),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Bytes, String> {
        self.inner
            .get_range(&self.path(key), range)
            .await
            .map_err(|e| e.to_string())
    }

    /// Uploads a local file in 8 MiB parts (exports and downloads can be
    /// gigabytes; they never sit in memory as a whole).
    pub async fn put_file(&self, key: &str, path: &std::path::Path) -> Result<u64, String> {
        use tokio::io::AsyncReadExt;
        let mut f = tokio::fs::File::open(path)
            .await
            .map_err(|e| e.to_string())?;
        let up = self
            .inner
            .put_multipart(&self.path(key))
            .await
            .map_err(|e| e.to_string())?;
        let mut w = object_store::WriteMultipart::new(up);
        let mut buf = vec![0u8; 8 << 20];
        let mut total = 0u64;
        loop {
            let n = f.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            total += n as u64;
            w.wait_for_capacity(4).await.map_err(|e| e.to_string())?;
            w.write(&buf[..n]);
        }
        w.finish().await.map_err(|e| e.to_string())?;
        Ok(total)
    }

    /// The size of a stored object, None when it does not exist.
    pub async fn size(&self, key: &str) -> Result<Option<u64>, String> {
        match self.inner.head(&self.path(key)).await {
            Ok(m) => Ok(Some(m.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// A stored object as a stream of chunks.
    pub async fn get_stream(
        &self,
        key: &str,
    ) -> Result<Option<futures::stream::BoxStream<'static, Result<Bytes, std::io::Error>>>, String>
    {
        use futures::StreamExt;
        match self.inner.get(&self.path(key)).await {
            Ok(r) => Ok(Some(
                r.into_stream()
                    .map(|c| c.map_err(std::io::Error::other))
                    .boxed(),
            )),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    pub async fn exists(&self, key: &str) -> bool {
        self.inner.head(&self.path(key)).await.is_ok()
    }

    /// Deletes every object under a key prefix (an export's files).
    pub async fn delete_prefix(&self, prefix: &str) -> Result<(), String> {
        use futures::TryStreamExt;
        let base = self.path(prefix.trim_end_matches('/'));
        let metas: Vec<_> = self
            .inner
            .list(Some(&base))
            .try_collect()
            .await
            .map_err(|e| e.to_string())?;
        for m in metas {
            match self.inner.delete(&m.location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(())
    }

    pub async fn delete(&self, key: &str) -> Result<(), String> {
        self.inner
            .delete(&self.path(key))
            .await
            .map_err(|e| e.to_string())
    }
}
