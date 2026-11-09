# Read automatically by gunicorn when it starts in this folder.
# 1 worker keeps memory low on the free plan (the ML model is loaded once);
# 8 threads let it serve many visitors at the same time.
workers = 1
threads = 8
timeout = 60
keepalive = 5

# Hardening: reject oversized or malformed requests before the app sees them.
limit_request_line = 4094
limit_request_fields = 50
limit_request_field_size = 8190
graceful_timeout = 20
worker_tmp_dir = "/dev/shm"
