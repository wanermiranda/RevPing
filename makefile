# revPingServer
#       author: Waner de Oliveira Miranda
#       course: DCC - SI - UFMG

CC = gcc

CFLAGS = -Icap -O0 -Wall 

LIBS = -lnet -lpcap -lcap 

RM = rm -f

OBJ = packetParser.o revPingServer.o probeSender.o main.o

VALGRIND = valgrind --tool=memcheck --leak-check=yes --show-reachable=yes

MAIN = revPingServer

all: $(OBJ) 
	@echo ""
	@echo " Compilando $(MAIN)"
	@$(CC) -o $(MAIN) $(CFLAGS) $(OBJ) $(LIBS)  
	@echo ""


%.o: ./src/%.c
	@echo " Compilando Objetos \"$@\""
	@$(CC) $(LIBS)  $< -c

clean:
	$(RM) $(MAIN) *.o
	clear
analysis: $(MAIN)
	$(VALGRIND) ./$(MAIN)

run: $(MAIN)
	./$(MAIN)

