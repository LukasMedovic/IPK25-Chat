PROJECT_NAME = ipk25chat-client
PROJECT_FILE = $(PROJECT_NAME).csproj
EXECUTABLE_NAME = $(PROJECT_NAME)
LOGIN = xmedovl00
ARCHIVE_NAME = $(LOGIN).zip
DOTNET_RID = linux-x64
PUBLISH_DIR = ./publish
PACK_FILES = Program.cs $(PROJECT_FILE) README.md Makefile

.PHONY: all build run clean pack

all: $(EXECUTABLE_NAME)

$(EXECUTABLE_NAME): build
	@echo "Kopirujem $(EXECUTABLE_NAME) do rootu..."
	@cp $(PUBLISH_DIR)/$(EXECUTABLE_NAME) .
	@echo "Hotovo. Spustitelny subor '$(EXECUTABLE_NAME)' je v roote."

build:
	@echo "Vytvaram projekt pre $(DOTNET_RID)..."
	@dotnet publish $(PROJECT_FILE) -c Release -r $(DOTNET_RID) --self-contained true -o $(PUBLISH_DIR)

run:
	@echo "Spustam projekt s argumentami: $(ARGS)"
	@dotnet run --project $(PROJECT_FILE) -- $(ARGS)

clean:
	@echo "Cistim projekt..."
	@dotnet clean $(PROJECT_FILE) -c Release
	@rm -rf bin obj $(PUBLISH_DIR) $(EXECUTABLE_NAME) $(ARCHIVE_NAME)
	@echo "Projekt vycisteny."

pack:
	@echo "Vytvaram archiv $(ARCHIVE_NAME)..."
	@zip $(ARCHIVE_NAME) $(PACK_FILES)
	@echo "Archiv $(ARCHIVE_NAME) vytvoreny."

