#include <windows.h>
#include <stdio.h>

typedef struct {
	WORD DOS_HEADER_MAGIC;
	DWORD DOS_HEADER_LFANEW;
	DWORD NT_HEADER_SIGNATURE;
	WORD FILE_HEADER_MACHINE;
	WORD FILE_HEADER_NUMBEROF_SECTIONS;
	WORD FILE_HEADER_SIZEOF_OPTIONAL_HEADERS;
	WORD OPTIONAL_HEADER_MAGIC;
	DWORD OPTIONAL_HEADER_SIZEOF_CODE;
	DWORD OPTIONAL_HEADER_SIZEOF_INIT_DATA;
	DWORD OPTIONAL_HEADER_SIZEOF_UNINIT_DATA;
	DWORD OPTIONAL_HEADER_ADDRESSOF_ENTRY_POINT;
	DWORD OPTIONAL_HEADER_BASEOF_CODE;
	union {
		DWORD OPTIONAL_HEADER_IMAGE_BASE;
		ULONGLONG OPTIONAL_HEADER_IMAGE_BASE64;
	};
	DWORD OPTIONAL_HEADER_SECTION_ALIGNMENT;
	DWORD OPTIONAL_HEADER_FILE_ALIGNMENT;
	DWORD OPTIONAL_HEADER_SIZEOF_IMAGE;
	DWORD OPTIONAL_HEADER_SIZEOF_HEADERS;
	IMAGE_DATA_DIRECTORY EXPORT_DIRECTORY;
	IMAGE_DATA_DIRECTORY IMPORT_DIRECTORY;
	IMAGE_DATA_DIRECTORY RESOURCE_DIRECTORY;
	IMAGE_DATA_DIRECTORY EXCEPTION_DIRECTORY;
	IMAGE_DATA_DIRECTORY SECURITY_DIRECTORY;
	IMAGE_DATA_DIRECTORY BASE_RELOC_DIRECTORY;
	IMAGE_DATA_DIRECTORY DEBUG_DIRECTORY;
	IMAGE_DATA_DIRECTORY ARCHITECTURE_DIRECTORY;
	IMAGE_DATA_DIRECTORY GLOBAL_PTR_DIRECTORY;
	IMAGE_DATA_DIRECTORY TLS_DIRECTORY;
	IMAGE_DATA_DIRECTORY LOAD_CONFIG_DIRECTORY;
	IMAGE_DATA_DIRECTORY BOUND_IMPORT_DIRECTORY;
	IMAGE_DATA_DIRECTORY IAT_DIRECTORY;
	IMAGE_DATA_DIRECTORY DELAY_IMPORT_DIRECTORY;
	IMAGE_DATA_DIRECTORY COM_DESCRIPTOR_DIRECTORY;

} PEInfo;

int check_file_type(FILE* fp) {
	if (fp == NULL) {
		printf("[!] Erro ao abrir arquivo!\n");
		return -1;
	}

	/*
	   Podemos saber se um arquivo é do tipo PE
	   examinando o conteúdo do primeiro campo
	   do cabeçalho NT (chamado Signature).

	   Podemos encontrar o endereço do início
	   do cabeçalho NT (por tanto do campo Signature)
	   através do campo e_lfanew do cabeçalho DOS,
	   que está localizado sempre no offset 0x3C.

	   Vamos então ler o conteúdo de 0x3C para obter
	   a localização do campo Signature e então ler
	   o conteúdo para saber se é um arquivo PE ou não.

	   Para ser um arquivo PE, a Signature deve ser igual
	   a "PE\0\0" (ou 0x50450000 em hex).
	*/

	DWORD peOffset;
	
	fseek(fp, 0x3C, SEEK_SET); // Pula o cursor para a posição 0x3C
	fread(&peOffset, sizeof(DWORD), 1, fp); // Lê o conteúdo da posição atual do cursor e salva em peOffset


	DWORD peSignature;
	fseek(fp, peOffset, SEEK_SET); // Pula para o endereço encontrada no passo anterior
	fread(&peSignature, sizeof(DWORD), 1, fp); // Lê a assinatura

	// Checa se a assinatura é igual a "PE\0\0" (0x00004550 em hex usando little-endian)
	if (peSignature != IMAGE_NT_SIGNATURE) {
		printf("[!] O arquivo não é um PE válido!\n");
		return -1;
	}

	/*
	   Os próximos 2 bytes depois da assinatura do cabeçalho NT
	   é o campo Machine, que é usado para identificar o tipo
	   de arquitetura sendo usada.

	   Podemos usar esse campo para verificar se o arquivo
	   é 32-bits ou 64-bits.
	*/

	WORD machine;

	fread(&machine, sizeof(WORD), 1, fp); // Lê o campo machine do cabeçalho NT

	// Checa se o arquivo é 32-bits ou 64-bits
	if (machine == IMAGE_FILE_MACHINE_I386) {
		printf("[+] Parsing a PE32 file...\n\n");
		return 32;
	}
	else if (machine == IMAGE_FILE_MACHINE_AMD64) {
		printf("[+] Parsing a PE32+ file...\n\n");
		return 64;
	}

	return 0;
}

/*
	Função para ler o DOS Header do arquivo
*/
PEInfo parse_dos_header(FILE* fp, PEInfo peInfo) {
	// Move o cursor para o inicio do arquivo
	fseek(fp, 0, SEEK_SET);

	// Lê os primeiros dois bytes (e_magic) e salva no campo DOS_HEADER_MAGIC do peInfo
	fread(&peInfo.DOS_HEADER_MAGIC, sizeof(WORD), 1, fp);

	// Move o cursor para o inicio do campo e_lfanew (sempre localizado em 0x3C)
	fseek(fp, 0x3C, SEEK_SET);

	// Lê o conteúdo (endereço do início do NT Headers) e salva no campo DOS_HEADER_LFANEW do peInfo
	fread(&peInfo.DOS_HEADER_LFANEW, sizeof(DWORD), 1, fp);

	// Imprime as informações
	printf("[ DOS HEADER ]\n\n");
	printf("  * e_magic: 0x%X\n", peInfo.DOS_HEADER_MAGIC);
	printf("  * e_lfanew: 0x%X\n", peInfo.DOS_HEADER_LFANEW);

	// Retorna o peInfo
	return peInfo;
}

PEInfo parse_nt_header64(FILE* fp, PEInfo peInfo) {
	
	// NT_HEADERS é do tipo IMAGE_NT_HEADERS64
	IMAGE_NT_HEADERS64 NT_HEADERS; 

	// Move o cursor para o endereço do inicio dos nt headers (salvo em e_lfanew do dos header)
	fseek(fp, peInfo.DOS_HEADER_LFANEW, SEEK_SET);

	// Salva o NT Headers em NT_HEADERS
	fread(&NT_HEADERS, sizeof(IMAGE_NT_HEADERS64), 1, fp);
	
	// Salva a assinatura
	peInfo.NT_HEADER_SIGNATURE = NT_HEADERS.Signature;

	// Salva os campos do FileHeader
	peInfo.FILE_HEADER_MACHINE = NT_HEADERS.FileHeader.Machine;
	peInfo.FILE_HEADER_NUMBEROF_SECTIONS = NT_HEADERS.FileHeader.NumberOfSections;
	peInfo.FILE_HEADER_SIZEOF_OPTIONAL_HEADERS = NT_HEADERS.FileHeader.SizeOfOptionalHeader;

	// Salva os campos do OptionalHeaders
	peInfo.OPTIONAL_HEADER_MAGIC = NT_HEADERS.OptionalHeader.Magic;
	peInfo.OPTIONAL_HEADER_SIZEOF_CODE = NT_HEADERS.OptionalHeader.SizeOfCode;
	peInfo.OPTIONAL_HEADER_ADDRESSOF_ENTRY_POINT = NT_HEADERS.OptionalHeader.AddressOfEntryPoint;
	peInfo.OPTIONAL_HEADER_BASEOF_CODE = NT_HEADERS.OptionalHeader.BaseOfCode;
	peInfo.OPTIONAL_HEADER_IMAGE_BASE64 = NT_HEADERS.OptionalHeader.ImageBase;
	peInfo.OPTIONAL_HEADER_SECTION_ALIGNMENT = NT_HEADERS.OptionalHeader.SectionAlignment;
	peInfo.OPTIONAL_HEADER_FILE_ALIGNMENT = NT_HEADERS.OptionalHeader.FileAlignment;
	peInfo.OPTIONAL_HEADER_SIZEOF_HEADERS = NT_HEADERS.OptionalHeader.SizeOfHeaders;
	peInfo.OPTIONAL_HEADER_SIZEOF_INIT_DATA = NT_HEADERS.OptionalHeader.SizeOfInitializedData;
	peInfo.OPTIONAL_HEADER_SIZEOF_UNINIT_DATA = NT_HEADERS.OptionalHeader.SizeOfUninitializedData;
	peInfo.OPTIONAL_HEADER_SIZEOF_IMAGE = NT_HEADERS.OptionalHeader.SizeOfImage;

	// Salva os Data Directories
	peInfo.EXPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	peInfo.IMPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	peInfo.RESOURCE_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	peInfo.EXCEPTION_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	peInfo.SECURITY_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	peInfo.BASE_RELOC_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	peInfo.DEBUG_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	peInfo.ARCHITECTURE_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
	peInfo.GLOBAL_PTR_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
	peInfo.TLS_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	peInfo.LOAD_CONFIG_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	peInfo.BOUND_IMPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	peInfo.IAT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	peInfo.DELAY_IMPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	peInfo.COM_DESCRIPTOR_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

	// Imprime as informações
	printf("\n[ NT Headers ]\n\n");
	printf("  * PE Signature:\n");
	printf("\tSignature: 0x%X\n", peInfo.NT_HEADER_SIGNATURE);
	printf("\n  * File Header:\n");
	printf("\tMachine: 0x%X\n", peInfo.FILE_HEADER_MACHINE);
	printf("\tNumberOfSections: 0x%X\n", peInfo.FILE_HEADER_NUMBEROF_SECTIONS);
	printf("\tSizeOfOptionalHeaders: 0x%X\n", peInfo.FILE_HEADER_SIZEOF_OPTIONAL_HEADERS);

	printf("\n  * Optional Headers:\n");
	printf("\tMagic: 0x%X\n", peInfo.OPTIONAL_HEADER_MAGIC);
	printf("\tSizeOfCode: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_CODE);
	printf("\tSizeOfInitializedData: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_INIT_DATA);
	printf("\tSizeOfUninitalizedData: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_UNINIT_DATA);
	printf("\tAddressOfEntryPoint: 0x%X\n", peInfo.OPTIONAL_HEADER_ADDRESSOF_ENTRY_POINT);
	printf("\tBaseOfCode: 0x%X\n", peInfo.OPTIONAL_HEADER_BASEOF_CODE);
	printf("\tImageBase: 0x%lld\n", peInfo.OPTIONAL_HEADER_IMAGE_BASE64);
	printf("\tSectionAlignment: 0x%X\n", peInfo.OPTIONAL_HEADER_SECTION_ALIGNMENT);
	printf("\tFileAlignment: 0x%X\n", peInfo.OPTIONAL_HEADER_FILE_ALIGNMENT);
	printf("\tSizeOfImage: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_IMAGE);
	printf("\tSizeOfHeaders: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_HEADERS);

	printf("\n  * Data Directories:\n");
	printf("\tExport Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.EXPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.EXPORT_DIRECTORY.Size);

	printf("\tImport Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.IMPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.IMPORT_DIRECTORY.Size);

	printf("\tResource Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.RESOURCE_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.RESOURCE_DIRECTORY.Size);

	printf("\tException Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.EXCEPTION_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.EXCEPTION_DIRECTORY.Size);

	printf("\tSecurity Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.SECURITY_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.SECURITY_DIRECTORY.Size);

	printf("\tBase Relocation Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.BASE_RELOC_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.BASE_RELOC_DIRECTORY.Size);

	printf("\tDebug Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.DEBUG_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.DEBUG_DIRECTORY.Size);

	printf("\tArchitecture Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.ARCHITECTURE_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.ARCHITECTURE_DIRECTORY.Size);

	printf("\tGlobal Pointer Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.GLOBAL_PTR_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.GLOBAL_PTR_DIRECTORY.Size);

	printf("\tTLS Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.TLS_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.TLS_DIRECTORY.Size);

	printf("\tLoad Config Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.LOAD_CONFIG_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.LOAD_CONFIG_DIRECTORY.Size);

	printf("\tBound Import Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.BOUND_IMPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.BOUND_IMPORT_DIRECTORY.Size);

	printf("\tIAT Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.IAT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.IAT_DIRECTORY.Size);

	printf("\tDelay Import Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.DELAY_IMPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.DELAY_IMPORT_DIRECTORY.Size);

	printf("\tCOM Descriptor Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.COM_DESCRIPTOR_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.COM_DESCRIPTOR_DIRECTORY.Size);

	// Retorna o peInfo
	return peInfo;
}

PEInfo parse_nt_header32(FILE* fp, PEInfo peInfo) {
	// NT_HEADERS é do tipo IMAGE_NT_HEADERS32
	IMAGE_NT_HEADERS32 NT_HEADERS;

	// Move o cursor para o endereço do inicio dos nt headers (salvo em e_lfanew do dos header)
	fseek(fp, peInfo.DOS_HEADER_LFANEW, SEEK_SET);

	// Salva o NT Headers em NT_HEADERS
	fread(&NT_HEADERS, sizeof(IMAGE_NT_HEADERS32), 1, fp);

	// Salva a assinatura
	peInfo.NT_HEADER_SIGNATURE = NT_HEADERS.Signature;

	// Salva os campos do FileHeader
	peInfo.FILE_HEADER_MACHINE = NT_HEADERS.FileHeader.Machine;
	peInfo.FILE_HEADER_NUMBEROF_SECTIONS = NT_HEADERS.FileHeader.NumberOfSections;
	peInfo.FILE_HEADER_SIZEOF_OPTIONAL_HEADERS = NT_HEADERS.FileHeader.SizeOfOptionalHeader;

	// Salva os campos do OptionalHeaders
	peInfo.OPTIONAL_HEADER_MAGIC = NT_HEADERS.OptionalHeader.Magic;
	peInfo.OPTIONAL_HEADER_SIZEOF_CODE = NT_HEADERS.OptionalHeader.SizeOfCode;
	peInfo.OPTIONAL_HEADER_ADDRESSOF_ENTRY_POINT = NT_HEADERS.OptionalHeader.AddressOfEntryPoint;
	peInfo.OPTIONAL_HEADER_BASEOF_CODE = NT_HEADERS.OptionalHeader.BaseOfCode;
	peInfo.OPTIONAL_HEADER_IMAGE_BASE = NT_HEADERS.OptionalHeader.ImageBase;
	peInfo.OPTIONAL_HEADER_SECTION_ALIGNMENT = NT_HEADERS.OptionalHeader.SectionAlignment;
	peInfo.OPTIONAL_HEADER_FILE_ALIGNMENT = NT_HEADERS.OptionalHeader.FileAlignment;
	peInfo.OPTIONAL_HEADER_SIZEOF_HEADERS = NT_HEADERS.OptionalHeader.SizeOfHeaders;
	peInfo.OPTIONAL_HEADER_SIZEOF_INIT_DATA = NT_HEADERS.OptionalHeader.SizeOfInitializedData;
	peInfo.OPTIONAL_HEADER_SIZEOF_UNINIT_DATA = NT_HEADERS.OptionalHeader.SizeOfUninitializedData;
	peInfo.OPTIONAL_HEADER_SIZEOF_IMAGE = NT_HEADERS.OptionalHeader.SizeOfImage;

	// Salva os Data Directories
	peInfo.EXPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	peInfo.IMPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	peInfo.RESOURCE_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
	peInfo.EXCEPTION_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	peInfo.SECURITY_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
	peInfo.BASE_RELOC_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	peInfo.DEBUG_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	peInfo.ARCHITECTURE_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE];
	peInfo.GLOBAL_PTR_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR];
	peInfo.TLS_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	peInfo.LOAD_CONFIG_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	peInfo.BOUND_IMPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
	peInfo.IAT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
	peInfo.DELAY_IMPORT_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	peInfo.COM_DESCRIPTOR_DIRECTORY = NT_HEADERS.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

	// Imprime as informações
	printf("\n[ NT Headers ]\n\n");
	printf("  * PE Signature:\n");
	printf("\tSignature: 0x%X\n", peInfo.NT_HEADER_SIGNATURE);
	printf("\n  * File Header:\n");
	printf("\tMachine: 0x%X\n", peInfo.FILE_HEADER_MACHINE);
	printf("\tNumberOfSections: 0x%X\n", peInfo.FILE_HEADER_NUMBEROF_SECTIONS);
	printf("\tSizeOfOptionalHeaders: 0x%X\n", peInfo.FILE_HEADER_SIZEOF_OPTIONAL_HEADERS);

	printf("\n  * Optional Headers:\n");
	printf("\tMagic: 0x%X\n", peInfo.OPTIONAL_HEADER_MAGIC);
	printf("\tSizeOfCode: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_CODE);
	printf("\tSizeOfInitializedData: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_INIT_DATA);
	printf("\tSizeOfUninitalizedData: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_UNINIT_DATA);
	printf("\tAddressOfEntryPoint: 0x%X\n", peInfo.OPTIONAL_HEADER_ADDRESSOF_ENTRY_POINT);
	printf("\tBaseOfCode: 0x%X\n", peInfo.OPTIONAL_HEADER_BASEOF_CODE);
	printf("\tImageBase: 0x%X\n", peInfo.OPTIONAL_HEADER_IMAGE_BASE);
	printf("\tSectionAlignment: 0x%X\n", peInfo.OPTIONAL_HEADER_SECTION_ALIGNMENT);
	printf("\tFileAlignment: 0x%X\n", peInfo.OPTIONAL_HEADER_FILE_ALIGNMENT);
	printf("\tSizeOfImage: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_IMAGE);
	printf("\tSizeOfHeaders: 0x%X\n", peInfo.OPTIONAL_HEADER_SIZEOF_HEADERS);

	printf("\n  * Data Directories:\n");
	printf("\tExport Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.EXPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.EXPORT_DIRECTORY.Size);

	printf("\tImport Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.IMPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.IMPORT_DIRECTORY.Size);

	printf("\tResource Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.RESOURCE_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.RESOURCE_DIRECTORY.Size);

	printf("\tException Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.EXCEPTION_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.EXCEPTION_DIRECTORY.Size);

	printf("\tSecurity Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.SECURITY_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.SECURITY_DIRECTORY.Size);

	printf("\tBase Relocation Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.BASE_RELOC_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.BASE_RELOC_DIRECTORY.Size);

	printf("\tDebug Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.DEBUG_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.DEBUG_DIRECTORY.Size);

	printf("\tArchitecture Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.ARCHITECTURE_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.ARCHITECTURE_DIRECTORY.Size);

	printf("\tGlobal Pointer Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.GLOBAL_PTR_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.GLOBAL_PTR_DIRECTORY.Size);

	printf("\tTLS Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.TLS_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.TLS_DIRECTORY.Size);

	printf("\tLoad Config Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.LOAD_CONFIG_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.LOAD_CONFIG_DIRECTORY.Size);

	printf("\tBound Import Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.BOUND_IMPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.BOUND_IMPORT_DIRECTORY.Size);

	printf("\tIAT Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.IAT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.IAT_DIRECTORY.Size);

	printf("\tDelay Import Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.DELAY_IMPORT_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.DELAY_IMPORT_DIRECTORY.Size);

	printf("\tCOM Descriptor Directory\n");
	printf("\t\tRVA: 0x%X\n", peInfo.COM_DESCRIPTOR_DIRECTORY.VirtualAddress);
	printf("\t\tSize: 0x%X\n", peInfo.COM_DESCRIPTOR_DIRECTORY.Size);

	// Retorna o peInfo
	return peInfo;
}

PEInfo parse_section_header(FILE* fp, PEInfo peInfo, int fileType) {
	// Aloca memória do tamanho de (numero_de_seções + tamanho_de_uma_seção) para ler os section headers
	IMAGE_SECTION_HEADER* SECTION_HEADERS = (IMAGE_SECTION_HEADER*)malloc(peInfo.FILE_HEADER_NUMBEROF_SECTIONS * sizeof(IMAGE_SECTION_HEADER));


	printf("\n[ SECTION HEADERS ]\n\n");

	// Itera de 0 até o número de seções
	for (int i = 0; i < peInfo.FILE_HEADER_NUMBEROF_SECTIONS; i++) {
		int offset;

		// Checa se o arquivo é 64-bits ou 32-bits para calcular o offset corretamente
		if (fileType == 64) {
			// Calcula o offset: endereço do inicio dos nt headers + tamanho dos nt headers + (tamanho do section header * i)
			offset = peInfo.DOS_HEADER_LFANEW + sizeof(IMAGE_NT_HEADERS64) + (IMAGE_SIZEOF_SECTION_HEADER * i);
		}
		else {
			// Calcula o offset: endereço do inicio dos nt headers + tamanho dos nt headers + (tamanho do section header * i)
			offset = peInfo.DOS_HEADER_LFANEW + sizeof(IMAGE_NT_HEADERS32) + (IMAGE_SIZEOF_SECTION_HEADER * i);
		}
		fseek(fp, offset, SEEK_SET);
		fread(&SECTION_HEADERS[i], IMAGE_SIZEOF_SECTION_HEADER, 1, fp);
		printf("  * %.8s:\n", SECTION_HEADERS[i].Name);
		printf("\tVirtualAddress: 0x%X\n", SECTION_HEADERS[i].VirtualAddress);
		printf("\tVirtualSize: 0x%X\n", SECTION_HEADERS[i].Misc.VirtualSize);
		printf("\tPointerToRawData: 0x%X\n", SECTION_HEADERS[i].PointerToRawData);
		printf("\tSizeOfRawData: 0x%X\n", SECTION_HEADERS[i].SizeOfRawData);
		printf("\tCharacteristics: 0x%X\n\n", SECTION_HEADERS[i].Characteristics);
	}

	free(SECTION_HEADERS); // Libera a memória
	SECTION_HEADERS = NULL; // Previne dangling pointers

	return peInfo;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("[!] Uso: %s <arquivo PE>\n", argv[0]);
		return -1;
	}

	FILE* fp = fopen(argv[1], "r");
	WORD fileType;
	fileType = check_file_type(fp); // se fileType for 32, o arquivo é 32-bits. Se for 64, o arquivo é 64-bits.

	// Checa se é um arquivo PE
	if (fileType <= 0) {
		printf("[!] Não é um arquivo PE válido!\n");
		return -1;
	}

	// Inicializa peInfo
	PEInfo peInfo;
	memset(&peInfo, 0, sizeof(PEInfo));

	peInfo = parse_dos_header(fp, peInfo);

	if (fileType == 64) {
		peInfo = parse_nt_header64(fp, peInfo);
	}
	else if (fileType == 32) {
		peInfo = parse_nt_header32(fp, peInfo);
	}
	else {
		printf("[!] Formato do arquivo invalido.\n");
		return -1;
	}

	peInfo = parse_section_header(fp, peInfo, fileType);

	fclose(fp);
	return 0;
}