EXE := "datagaze"

build:
	go build -o $(EXE) main.go 

clean:
	rm -f ./$(EXE)

run:
	make build 
	sudo ./$(EXE)	

.PHONY: build clean run