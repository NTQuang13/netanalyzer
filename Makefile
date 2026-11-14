PY ?= python
LAB ?= nta

.PHONY: install synth test eval report bench compare lab-build lab-up lab-setup lab-pcaps lab-down lab-all

install:            ## tạo venv + cài thư viện
	python3 -m venv .venv && .venv/bin/pip install -U pip && .venv/bin/pip install -r requirements.txt

synth:              ## sinh pcap tổng hợp (tái lập 100%)
	$(PY) -m netanalyzer.cli synth --out pcaps/synthetic

test:               ## chạy toàn bộ test
	$(PY) -m pytest -v

eval:               ## bảng TP/FN/FP trên mọi pcap có trong ground_truth.yml
	$(PY) -m netanalyzer.cli evaluate

report:             ## báo cáo HTML mẫu
	$(PY) -m netanalyzer.cli analyze pcaps/synthetic/mixed.pcap --report reports/sample_report.html --quiet

bench:              ## đo gói/giây (scapy vs fast): make bench PCAP=pcaps/lab/portscan.pcap
	$(PY) -m netanalyzer.cli bench $(PCAP)

compare:            ## đối chiếu tshark
	$(PY) tools/compare_tools.py pcaps/synthetic/*.pcap

lab-build:          ## build image dùng chung cho lab
	docker build -t nta-node:latest lab/

lab-up:
	sudo containerlab deploy -t lab/topology.clab.yml

lab-setup:          ## cấu hình VLAN, IP, DHCP, mirror
	bash lab/setup.sh

lab-pcaps:          ## bắt pcap cho mọi kịch bản vào pcaps/lab/
	bash lab/run_all.sh

lab-down:
	sudo containerlab destroy -t lab/topology.clab.yml --cleanup

lab-all: lab-build lab-up lab-setup lab-pcaps eval
