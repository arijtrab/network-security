.PHONY: install test lint demo-good demo-bad demo-full train lab-up lab-down
install:   ; python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
test:      ; pytest -q
lint:      ; yamllint -c .yamllint configs/ policies/
demo-good: ; ./run_local.sh configs
demo-bad:  ; ./run_local.sh demo/vulnerable
demo-full: ; ./run_local.sh demo/vulnerable-full
train:     ; python ml/make_dataset.py && python ml/train.py
lab-up:    ; docker compose -f lab/docker-compose.yml up -d
lab-down:  ; docker compose -f lab/docker-compose.yml down
