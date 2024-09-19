package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/eiannone/keyboard"
)

var (
	verify      = flag.Bool("c", false, "Verificar os hashes dos arquivos")
	aggregate   = flag.Bool("a", false, "Salvar novos hashes em um arquivo hashes.b3")
	copyHashes  = flag.Bool("j", false, "Copiar os hashes de arquivos .b3 para hashes.b3")
	splitHashes = flag.Bool("s", false, "Dividir o hashes.b3 em arquivos .b3 individuais")
	removeFiles = flag.Bool("r", false, "Remover arquivos .b3, exceto hashes.b3")
	hdd         = flag.Bool("hdd", false, "Otimizar para HD externo")
	cat         = flag.Bool("cat", false, "Usar cat para ler o arquivo")
	Vversion    = flag.Bool("v", false, "Exibe a versao")
	version     = flag.Bool("version", false, "")
)

// Variáveis para contar as ocorrências
var (
	successCount      int
	missmatchCount    int
	fileNotFoundCount int
	hashNotFoundCount int
	errorCount        int
	skipedCount       int
	calculedCount     int
)

/*

func calculateB3(path string) (string, error) {
	args := []string{path}
	if *useHDD {
		// Adiciona otimizações para HD externo
		args = append(args, "--num-threads=1", "--no-mmap")
	}
	cmd := exec.Command("b3sum", args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Divide a saída para pegar somente o hash
	parts := strings.SplitN(strings.TrimSpace(string(output)), " ", 2)
	if len(parts) < 1 {
		return "", fmt.Errorf("❗ Formato inesperado na saída do b3sum para o arquivo %s", path)
	}

	return parts[0], nil
}


*/

// --no-mmap --num-threads=1

// Usa 'cat arquivo | b3sum' para otimizar para HD externo
func calculateB3WithCat(path string) (string, error) {
	cat := exec.Command("cat", path)
	b3sum := exec.Command("b3sum")

	// Cria um pipe para conectar a saída de 'cat' à entrada de 'b3sum'
	stdoutPipe, err := cat.StdoutPipe()
	if err != nil {
		return "", err
	}

	if err := cat.Start(); err != nil {
		return "", err
	}

	b3sum.Stdin = stdoutPipe

	output, err := b3sum.Output()
	if err != nil {
		return "", err
	}

	if err := cat.Wait(); err != nil {
		return "", err
	}

	// Divide a saída para pegar somente o hash
	parts := strings.SplitN(strings.TrimSpace(string(output)), " ", 2)
	if len(parts) < 1 {
		errorCount++
		return "", fmt.Errorf("❗ Formato inesperado na saída do b3sum para o arquivo %s", path)
	}

	return parts[0], nil
}

// Calcula o hash
func calculateB3(path string) (string, error) {
	var cmd *exec.Cmd
	if *cat && runtime.GOOS != "windows" {
		return calculateB3WithCat(path)
	} else if *hdd {
		cmd = exec.Command("b3sum", path, "--no-mmap", "--num-threads=1")
	} else {
		cmd = exec.Command("b3sum", path)

	}
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	// Divide a saída para pegar somente o hash
	parts := strings.SplitN(strings.TrimSpace(string(output)), " ", 2)
	if len(parts) < 1 {
		errorCount++
		return "", fmt.Errorf("❗ Formato inesperado na saída do b3sum para o arquivo %s", path)
	}

	return parts[0], nil
}

// Lê o hash do arquivo .b3
func readHashFromFile(b3FilePath string) (string, error) {
	data, err := os.ReadFile(b3FilePath)
	if err != nil {
		errorCount++
		return "", fmt.Errorf("❗ Erro ao ler o arquivo %s: %v", b3FilePath, err)
	}

	// Divide em hash e nome do arquivo
	parts := strings.SplitN(string(data), "  ", 2)
	if len(parts) != 2 {
		errorCount++
		return "", fmt.Errorf("❗ Formato inválido no arquivo %s", b3FilePath)
	}

	return parts[0], nil
}

// Salva o hash BLAKE3 em um arquivo .b3 correspondente ao arquivo original, usando somente o nome do arquivo.
func saveHashToFile(filePath, hash, dir string) error {
	relPath, err := filepath.Rel(dir, filePath)
	if err != nil {
		return err
	}
	b3FilePath := filepath.Join(dir, relPath) + ".b3"
	file, err := os.Create(b3FilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Usar somente o nome do arquivo, sem o caminho completo
	fileName := filepath.Base(filePath)

	_, err = fmt.Fprintf(file, "%s  %s\n", hash, fileName)
	return err
}

// Salva todos os hashes BLAKE3 em um único arquivo hashes.b3.
func saveAllHashes(hashes map[string]string, dir string) error {
	file, err := os.Create(filepath.Join(dir, "hashes.b3"))
	if err != nil {
		return err
	}
	defer file.Close()

	for filePath, hash := range hashes {
		relPath, err := filepath.Rel(dir, filePath)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(file, "%s  %s\n", hash, relPath)
		if err != nil {
			return err
		}
	}
	return nil
}

// Lê os hashes existentes de hashes.b3 e retorna um mapa com os caminhos dos arquivos e seus hashes.
func readExistingHashes(dir string) (map[string]string, error) {
	hashes := make(map[string]string)

	file, err := os.Open(filepath.Join(dir, "hashes.b3"))
	if err != nil {
		if os.IsNotExist(err) {
			return hashes, nil // Arquivo não existe ainda, retornar mapa vazio
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) == 2 {
			hashes[filepath.Join(dir, parts[1])] = parts[0]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hashes, nil
}

// Verifica o hash BLAKE3 de um arquivo em relação ao arquivo .b3 correspondente.
func verifyHashFromFile(filePath, expectedHash string) error {
	calculatedHash, err := calculateB3(filePath)
	if err != nil {
		errorCount++
		return fmt.Errorf("❗ Erro ao calcular o hash do arquivo %s: %v", filePath, err)
	}

	if expectedHash != calculatedHash {
		fmt.Printf("❌ %s (⚙️: %s, 🤞: %s)\n", filePath, calculatedHash, expectedHash)
		missmatchCount++
	} else {
		fmt.Printf("✅ %s\n", filePath)
		successCount++
	}

	return nil
}

// Verifica se há arquivos listados no hashes.b3 que não existem no sistema de arquivos
func verifyOrphansFromFile(existingHashes map[string]string) error {
	// Percorre os hashes existentes e verifica se cada arquivo está presente no sistema de arquivos
	for path := range existingHashes {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			fmt.Printf("🔍📂 %s\n", path)
			fileNotFoundCount++
		}
	}
	return nil
}

// Percorre recursivamente o diretório e calcula/verifica os hashes BLAKE3 dos arquivos.
func processDirectory(dir string, verify, aggregate bool, existingHashes map[string]string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Verifica .b3 orphans
		if verify && !aggregate && !strings.HasSuffix(path, "hashes.b3") {
			originalFilePath := strings.TrimSuffix(path, ".b3")
			if _, err := os.Stat(originalFilePath); os.IsNotExist(err) {
				fmt.Printf("🔍📂 %s\n", path)
				fileNotFoundCount++

			}
		}

		// Ignora diretórios e arquivos .b3
		if info.IsDir() || strings.HasSuffix(path, ".b3") {
			return nil
		}

		// Verificação de arquivos
		if verify {
			if aggregate {
				// Se a flag -a está ativa e -c também está ativa, lê hashes.b3 e verifica os arquivos
				if hash, exists := existingHashes[path]; exists {
					return verifyHashFromFile(path, hash)
				}
				fmt.Printf("🔍⛏️  %s\n", path)
				hashNotFoundCount++

			} else {
				// Verifica o arquivo .b3 correspondente
				b3FilePath := path + ".b3"
				if _, err := os.Stat(b3FilePath); os.IsNotExist(err) {
					fmt.Printf("🔍⛏️  %s\n", path)
					hashNotFoundCount++

					return nil
				}
				hash, err := readHashFromFile(b3FilePath)
				if err != nil {
					return err
				}
				return verifyHashFromFile(path, hash)
			}
		} else {
			// Agregação de hashes
			if aggregate {
				if _, exists := existingHashes[path]; exists {
					fmt.Printf("⏭️ %s\n", path)
					skipedCount++
					return nil
				}
				fmt.Printf("⚙️ %s\n", path)
				hash, err := calculateB3(path)
				if err != nil {
					return err
				}
				calculedCount++
				existingHashes[path] = hash
			} else {
				// Geração de arquivos .b3 individuais
				if _, err := os.Stat(path + ".b3"); !os.IsNotExist(err) {
					fmt.Printf("⏭️ %s\n", path)
					skipedCount++
					return nil
				}
				fmt.Printf("⚙️ %s\n", path)
				hash, err := calculateB3(path)
				if err != nil {
					return err
				}
				calculedCount++
				return saveHashToFile(path, hash, dir)
			}
		}

		return nil
	})
}

// Copia os hashes de arquivos .b3 individuais para hashes.b3
func copyHashesToFile(dir string, existingHashes map[string]string) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Ignorar diretórios e arquivos que não são .b3
		if info.IsDir() || !strings.HasSuffix(path, ".b3") || strings.HasSuffix(path, "hashes.b3") {
			return nil
		}

		// Ler hash do arquivo .b3
		hash, err := readHashFromFile(path)
		if err != nil {
			return err
		}

		// Extrair o nome do arquivo correspondente ao .b3
		originalFilePath := strings.TrimSuffix(path, ".b3")

		// Adicionar ao mapa de hashes existentes
		existingHashes[originalFilePath] = hash

		return nil
	})
	if err != nil {
		return err
	}

	// Salvar todos os hashes em hashes.b3
	return saveAllHashes(existingHashes, dir)
}

// Cria arquivos .b3 individuais a partir de hashes.b3
func splitHashesToFiles(dir string) error {
	hashes, err := readExistingHashes(dir)
	if err != nil {
		return fmt.Errorf("❗ Erro ao ler o arquivo hashes.b3: %v", err)
	}

	for filePath, hash := range hashes {
		err = saveHashToFile(filePath, hash, dir)
		if err != nil {
			return fmt.Errorf("❗ Erro ao criar arquivo .b3 para %s: %v", filePath, err)
		}
	}
	return nil
}

// Remove arquivos .b3, exceto hashes.b3
func removeB3Files(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		//path == filepath.Join(dir, "hashes.b3"

		// Ignorar diretórios e arquivos que não são .b3
		if info.IsDir() || strings.HasSuffix(path, "hashes.b3") || !strings.HasSuffix(path, ".b3") {
			return nil
		}

		fmt.Printf("🗑️ Removendo arquivo .b3: %s\n", path)
		return os.Remove(path)
	})
}

// Verifica se um comando está disponível no sistema
func isCommandAvailable(cmdName string) bool {
	cmd := exec.Command(cmdName, "--version")
	return cmd.Run() == nil
}

// Pergunta ao usuário se deseja prosseguir com a instalação de um pacote
func askToInstall(packageName, method string) bool {
	fmt.Printf("❓ '%s' não está instalado. Deseja instalar via %s [y/n]? ", packageName, method)
	if err := keyboard.Open(); err != nil {
		panic(err)
	}
	defer keyboard.Close()

	for {
		char, _, err := keyboard.GetSingleKey()
		if err != nil {
			panic(err)
		}
		fmt.Println()
		switch char {
		case 'y', 'Y':
			return true
		case 'n', 'N':
			fmt.Printf("❌ Instalação de '%s' cancelada.\n", packageName)
			return false
		}
	}
}

// Executa o comando de instalação para Rust ou b3sum
func installPackage(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Falha ao instalar '%s'. Verifique sua conexão ou permissões.\n", command)
		return err
	}
	fmt.Printf("✅ '%s' instalado com sucesso.\n", command)
	return nil
}

func main() {
	flag.Parse()

	if *version || *Vversion {
		print("Picohash 1.0\n")
		return
	}

	// Verifica se o b3sum está disponível
	if !isCommandAvailable("b3sum") {
		if askToInstall("b3sum", "cargo") {
			if !isCommandAvailable("cargo") {
				fmt.Println("❌ 'cargo' não encontrado.")
				if askToInstall("Rust", "script oficial") {
					if err := installPackage("sh", "-c", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"); err != nil {
						return
					}
				} else {
					fmt.Println("❌ O programa requer 'cargo' para instalar 'b3sum'.")
					return
				}
			}
			// Instala o b3sum via cargo
			if err := installPackage("cargo", "install", "b3sum"); err != nil {
				return
			}
		} else {
			fmt.Println("❌ O programa requer 'b3sum' para funcionar. Instale-o antes de prosseguir.")
			return
		}
		fmt.Println("✅ Tudo pronto para continuar!")
		fmt.Println()
	}

	// Define o diretório padrão como "."
	dir := "."

	// Verifica se há argumentos fornecidos além das flags
	if len(flag.Args()) > 0 {
		// O primeiro argumento após as flags é considerado o diretório a ser processado
		dir = flag.Arg(0)
	}

	// Lê os hashes existentes de hashes.b3 se a flag -a, -j ou -s estiver ativa
	existingHashes := make(map[string]string)
	if *aggregate || *copyHashes || *splitHashes {
		var err error
		existingHashes, err = readExistingHashes(dir)
		if err != nil {
			fmt.Printf("❗ Erro ao ler o arquivo hashes.b3: %v\n", err)
			return
		}
	}

	// Copiar os hashes de arquivos .b3 para hashes.b3
	if *copyHashes {
		fmt.Println("📂 Copiando hashes de arquivos .b3 para hashes.b3...")
		if err := copyHashesToFile(dir, existingHashes); err != nil {
			fmt.Printf("❗ Erro ao copiar os hashes: %v\n", err)
			return
		}
		fmt.Println("✅ Cópia concluída.")
		return
	}

	// Dividir o hashes.b3 em arquivos .b3 individuais
	if *splitHashes {
		fmt.Println("📂 Dividindo hashes.b3 em arquivos .b3 individuais...")
		if err := splitHashesToFiles(dir); err != nil {
			fmt.Printf("❗ Erro ao dividir hashes.b3: %v\n", err)
			return
		}
		fmt.Println("✅ Divisão concluída.")
		return
	}

	// Remover arquivos .b3, exceto hashes.b3
	if *removeFiles {
		fmt.Println("📂 Removendo arquivos .b3, exceto hashes.b3...")

		if err := removeB3Files(dir); err != nil {
			fmt.Printf("❗ Erro ao remover arquivos .b3: %v\n", err)
			return
		}
		fmt.Println()
		fmt.Println("✅ Remoção concluída.")
		return
	}

	if *verify && *aggregate {
		// Verificar arquivos .b3 sem arquivos correspondentes
		if err := verifyOrphansFromFile(existingHashes); err != nil {
			fmt.Printf("❗ Erro ao verificar arquivos orfaos do hashes.b3: %v\n", err)
		}
	}

	// Processa o diretório com base nas flags fornecidas
	if err := processDirectory(dir, *verify, *aggregate, existingHashes); err != nil {
		fmt.Printf("❗ Erro ao processar o diretório: %v\n", err)
		return
	}

	// Se a flag -a estiver ativa, salva os hashes agregados em hashes.b3
	if *aggregate && !*verify {
		println()
		fmt.Println("📂 Salvando todos os hashes agregados em hashes.b3...")
		if err := saveAllHashes(existingHashes, dir); err != nil {
			fmt.Printf("❗ Erro ao salvar os hashes: %v\n", err)
		} else {
			fmt.Println("✅ Todos os hashes foram salvos com sucesso em hashes.b3.")
		}
	}

	// Exibir o resumo no final
	if *verify {
		fmt.Printf("\n")
		fmt.Printf("✅ %d / ❌ %d / 🔍 📂 %d / 🔍 ⛏️ %d / ❗ %d\n", successCount, missmatchCount, fileNotFoundCount, hashNotFoundCount, errorCount)

	} else {
		fmt.Printf("\n")
		fmt.Printf("⚙️ %d / ⏭️ %d\n", calculedCount, skipedCount)
	}

}
