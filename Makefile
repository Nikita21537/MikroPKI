.PHONY: help install test clean run-example

help:
	@echo "Available commands:"
	@echo "  install      Install dependencies"
	@echo "  test         Run tests"
	@echo "  clean        Clean build artifacts"
	@echo "  run-example  Run example CA initialization"

install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest tests/ -v

clean:
	rm -rf build/ dist/ *.egg-info/
	rm -rf pki/ logs/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

run-example:
	@echo "Creating passphrase file..."
	@mkdir -p secrets
	@echo "mysecurepassphrase" > secrets/ca.pass
	@echo "Initializing Root CA..."
	@micropki ca init \
		--subject "/CN=Example Root CA/O=MicroPKI/C=US" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file secrets/ca.pass \
		--out-dir ./pki \
		--validity-days 3650 \
		--log-file ./logs/ca-init.log
	@echo "CA initialized successfully!"
	@echo "Certificate info:"
	@openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before:|Not After:"