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

#[allow(dead_code)] // streaming helpers used by the portal downloads (next commit)
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

    /// The size of a stored object, None when it does not exist.
    pub async fn size(&self, key: &str) -> Result<Option<u64>, String> {
        match self.inner.head(&self.path(key)).await {
            Ok(m) => Ok(Some(m.size)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// A stored object as a stream of chunks (for large files).
    pub async fn stream(
        &self,
        key: &str,
        range: Option<std::ops::Range<u64>>,
    ) -> Result<Option<futures::stream::BoxStream<'static, Result<Bytes, String>>>, String> {
        use futures::StreamExt;
        let opts = object_store::GetOptions {
            range: range.map(object_store::GetRange::Bounded),
            ..Default::default()
        };
        match self.inner.get_opts(&self.path(key), opts).await {
            Ok(r) => Ok(Some(
                r.into_stream()
                    .map(|c| c.map_err(|e| e.to_string()))
                    .boxed(),
            )),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    /// Uploads a local file in parts of 8 MiB, without reading it into memory.
    pub async fn put_file(&self, key: &str, file: &std::path::Path) -> Result<u64, String> {
        use tokio::io::AsyncReadExt;
        let mut f = tokio::fs::File::open(file)
            .await
            .map_err(|e| e.to_string())?;
        let up = self
            .inner
            .put_multipart(&self.path(key))
            .await
            .map_err(|e| e.to_string())?;
        let mut w = object_store::WriteMultipart::new_with_chunk_size(up, 8 << 20);
        let mut buf = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = f.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            w.wait_for_capacity(4).await.map_err(|e| e.to_string())?;
            w.write(&buf[..n]);
            total += n as u64;
        }
        w.finish().await.map_err(|e| e.to_string())?;
        Ok(total)
    }

    pub async fn exists(&self, key: &str) -> bool {
        self.inner.head(&self.path(key)).await.is_ok()
    }

    pub async fn delete(&self, key: &str) -> Result<(), String> {
        self.inner
            .delete(&self.path(key))
            .await
            .map_err(|e| e.to_string())
    }
}
