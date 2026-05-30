TARGET := sigma_filter.bpf.o
SRC := sigma_filter.c
CLANG ?= clang

all: $(TARGET)

ml_weights.h: ../scripts/train_ml.py
	python3 ../scripts/train_ml.py

$(TARGET): $(SRC) ml_weights.h
	$(CLANG) -O2 -g -target bpf -c $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
