all: check-zonemd check-digestify

check-zonemd:
	flake8 zonemd.py && pylint zonemd.py || true

check-digestify:
	flake8 digestify.py && pylint digestify.py
