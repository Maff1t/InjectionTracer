#include "PE32.h"

PEFile32::PEFile32(const std::string& _filename)
{
	if (!init_mapping_view(_filename)) {
		errorLog("init_mapping_view error");
	}
}

W::IMAGE_OPTIONAL_HEADER32& PEFile32::opt_header() const
{
	auto opt_header_ptr = reinterpret_cast<W::PIMAGE_OPTIONAL_HEADER32>(m_view
		+ dos_header().e_lfanew + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER));
	return *opt_header_ptr;
}

bool PEFile32::isValidPe32()
{
	
	auto pe_header = this->pe_header();
	return is_file_valid() &&
		((pe_header.Machine & IMAGE_FILE_32BIT_MACHINE) == IMAGE_FILE_32BIT_MACHINE);
}

void PEFile32::fixBaseAddress(W::DWORD newBaseAddress)
{
	auto& header = this->opt_header();
	verboseLog("Fix PE Dump", "Modifying base address from %x to %x", header.ImageBase, newBaseAddress);
	header.ImageBase = newBaseAddress;
}

void PEFile32::fixAlign()
{
	auto& header = this->opt_header();
	verboseLog("Fix PE Dump", "Modifying file alignment from %x to %x", header.FileAlignment, header.SectionAlignment);
	header.FileAlignment = header.SectionAlignment;
}

void PEFile32::fixSections()
{
	auto headers = this->section_headers();
	for (const auto header : headers)
	{
		verboseLog("Fix PE Dump", "Fixing section %s", header->Name);
		// PointerToRawData must be equal to VirtualAddress
		header->PointerToRawData = header->VirtualAddress;
		W::DWORD new_size = header->SizeOfRawData;
		W::DWORD alignment = this->opt_header().SectionAlignment;
		if (new_size % alignment != 0)
		{
			// Not page aligned? Round up to next page-aligned size
			new_size = alignment * (1 + new_size / alignment);
		}
		header->SizeOfRawData = new_size;
	}
}

void PEFile32::fixRelocSection()
{
	auto headers = this->section_headers();
	for (const auto header : headers)
	{
		if (!strcmp ((const char *)header->Name, ".reloc")) {
			header->SizeOfRawData = 0;
			verboseLog("Fix PE Dump", "Modified size of .reloc section to 0");
			return;
		}
	}
}

void PEFile32::disableASLR()
{
	auto& optHeader = this->opt_header();
	verboseLog("Fix PE Dump", "Disabling ASLR for this executable");
	optHeader.DllCharacteristics = optHeader.DllCharacteristics & ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
}


size_t PEFile32::headers_size() const
{
	return sizeof(W::IMAGE_DOS_HEADER) + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER) + sizeof(W::IMAGE_OPTIONAL_HEADER32);
}