# Performance

node-rs is built for brands with up to tens of thousands of articles on one small instance. The load test (`src/tests_integration.rs`, node-go's `TestLoad`) seeds **10 000 products, 60 000 variants (EANs) and 40 000 images** into a fresh SQLite node and measures the requests retailers and their software make most:

```sh
NODE_RS_LOAD_TEST=1 cargo test load_test -- --nocapture                 # 10 000 products, about a minute
NODE_RS_LOAD_TEST=1 NODE_RS_LOAD_PRODUCTS=50000 cargo test --release load_test -- --nocapture
```

CI runs it on every change and fails when a request's 95th percentile exceeds its budget: 300 ms for pages, 50 ms for a single EAN lookup, 800 ms for bulk EAN lookups and `/changes` pages of 500 entries. The budgets are generous for slow CI machines and still catch a missing index or an N+1 query, which are 10–100× slower.

A run of the debug build (the slowest configuration; dependencies optimised, node-rs itself not) on an 8-core development machine, November 2026:

| Request | runs | p50 | p95 |
|---|---:|---:|---:|
| portal browse: first page | 30 | 9.2 ms | 10.6 ms |
| portal browse: filter season+type | 30 | 15.1 ms | 18.8 ms |
| portal browse: next page (walk 50 pages) | 50 | 10.3 ms | 12.2 ms |
| portal search: style number | 30 | 14.5 ms | 20.4 ms |
| portal search: word | 30 | 16.7 ms | 22.3 ms |
| portal facets | 30 | 48.9 ms | 63.6 ms |
| portal product page | 50 | 15.3 ms | 20.0 ms |
| portal EAN list (100 EANs) | 40 | 128.0 ms | 175.3 ms |
| `/changes` page (limit 500, full snapshot, 222 pages) | 222 | 29.8 ms | 126.3 ms |
| `/products:by-gtin` GET (1 EAN) | 200 | 2.5 ms | 3.1 ms |
| `/products:by-gtin` POST (500 EANs) | 20 | 599.5 ms | 692.8 ms |
| `/products` list page (limit 100) | 30 | 109.5 ms | 166.0 ms |
| admin catalog list | 30 | 6.3 ms | 10.9 ms |

Seeding took 25 seconds. The release build is several times faster on the bulk requests.
