#!/bin/bash
echo "==> mypy <=="
mypy --strict .
echo "==> black <=="
black --diff .
echo "==> pylint <=="
pylint --disable=C0103,C0115,C0116,C0301,R0903 --jobs=0 ./*.py lib/*.py
