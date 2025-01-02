EXE := "datagaze"
ELF_FILE := "data_gaze.o"

build:
	mkdir -p ./build
	go build -o ./build/$(EXE) main.go 

clean:
	rm -f ./$(EXE)

run:
	cp $(ELF_FILE) ./build/$(ELF_FILE)
	make build 
	sudo ./build/$(EXE)	

.PHONY: build clean run