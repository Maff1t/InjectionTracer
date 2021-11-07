#include "PE64.h"

PEFile64::PEFile64(const std::string& _filename)
{
	if (!init_mapping_view(_filename))
		ERR("init_mapping_view error");
}

W::IMAGE_OPTIONAL_HEADER64& PEFile64::opt_header() const
{
	auto opt_header_ptr = reinterpret_cast<W::PIMAGE_OPTIONAL_HEADER64>(m_view
		+ dos_header().e_lfanew + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER));
	return *opt_header_ptr;
}

bool PEFile64::isValidPe64()
{
	auto pe_header = this->pe_header();

	return is_file_valid() &&
		((pe_header.Machine & IMAGE_FILE_32BIT_MACHINE) != IMAGE_FILE_32BIT_MACHINE);
}

void PEFile64::fixBaseAddress(W::LPVOID newBaseAddress)
{
	auto& header = this->opt_header();
	if (header.ImageBase != (W::ULONGLONG)newBaseAddress) {
		VERBOSE("Fix PE Dump", "Modifying base address from %p to %p", header.ImageBase, newBaseAddress);
		header.ImageBase = (W::ULONGLONG)newBaseAddress;
	}
}

void PEFile64::fixAlign()
{
	auto& header = this->opt_header();
	VERBOSE("Fix PE Dump", "Modifying file alignment from %x to %x", header.FileAlignment, header.SectionAlignment);
	header.FileAlignment = header.SectionAlignment;
}

void PEFile64::fixSections()
{
	auto headers = this->section_headers();
	for (const auto header : headers)
	{
		// PointerToRawData must be equal to VirtualAddress
		header->PointerToRawData = header->VirtualAddress;
		W::DWORD new_size = header->SizeOfRawData;
		W::DWORD alignment = this->opt_header().SectionAlignment;
		if (new_size % alignment != 0)
		{
			// Not page aligned? Round up to next page-aligned size
			new_size = alignment * (1 + new_size / alignment);
		}
		VERBOSE("Fix PE Dump", "Modifying section %s raw size from %x to %x", header->Name, header->SizeOfRawData, new_size);
		header->SizeOfRawData = new_size;
	}
}

void PEFile64::fixRelocSection()
{
	auto headers = this->section_headers();
	for (const auto header : headers)
	{
		if (!strcmp((const char*)header->Name, ".reloc")) {
			header->SizeOfRawData = 0;
			VERBOSE("Fix PE Dump", "Modified size of .reloc section to 0");
			return;
		}
	}
}

void PEFile64::disableASLR()
{
	auto& optHeader = this->opt_header();
	VERBOSE("Fix PE Dump", "Disabling ASLR for this executable");
	optHeader.DllCharacteristics = optHeader.DllCharacteristics & ~(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);
}

std::size_t PEFile64::headers_size() const noexcept
{
	return sizeof(W::IMAGE_DOS_HEADER) + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER) + sizeof(W::IMAGE_OPTIONAL_HEADER64);
}