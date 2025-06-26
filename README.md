Nothing


批量使用：curl -X POST "http://localhost:8000/audit" -H "Content-Type: application/json" -d "{\"urls\": [\"https://research.org/sample1.pdf\", \"https://research.org/sample2.pdf\"]}"
最大并发5个，做文本截断处理
