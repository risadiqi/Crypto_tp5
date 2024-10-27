# On purge la liste des suffixes utilisés pour les règles implicites
.SUFFIXES:

# On ajoute simplement les extensions dont on a besoin
.SUFFIXES:.cpp .o

# Nom de l'exécutable
EXEC=tp6

# Liste des fichiers sources séparés par des espaces
SOURCES=main_DSA.cpp

# Liste des fichiers objets
OBJETS=$(SOURCES:%.cpp=%.o)

# Compilateur et options de compilation
CCPP=g++
CFLAGS= -W -Wall -Wextra -pedantic -std=c++0x -I /usr/X11R6/include
# Ajout de -lssl et -lcrypto dans LFLAGS pour lier OpenSSL
LFLAGS= -L . -L /usr/X11R6/lib -lpthread -lX11 -lXext -Dcimg_use_xshm -lm -lgmp -lssl -lcrypto

# Règle explicite de construction de l'exécutable
$(EXEC):$(OBJETS) Makefile
	$(CCPP) -o  $(EXEC) $(OBJETS) $(LFLAGS)

.cpp.o:
	$(CCPP) $(CFLAGS) -c $< -o $@

clean:
	rm $(OBJETS)

clear:
	rm $(EXEC)

depend:
	sed -e "/^#DEPENDANCIES/,$$ d" Makefile >dependances
	echo "#DEPENDANCIES" >> dependances
	$(CCPP) -MM $(SOURCES) >> dependances
	cat dependances >Makefile
	rm dependances

#DEPENDANCIES
main_DSA.o: main_DSA.cpp 
