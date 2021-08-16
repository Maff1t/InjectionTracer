#include "PE32.h"

PEFile32::PEFile32(const std::string& _filename)
{
	if (!init_mapping_view(_filename)) {
		ERR("init_mapping_view error");
	}

	if (!is_file_valid()) {
		ERR("Invalid PE header");
	}

	auto pe_header = this->pe_header();
	if ((pe_header.Machine & IMAGE_FILE_32BIT_MACHINE) != IMAGE_FILE_32BIT_MACHINE) {
		ERR("Bitness ERR");
	}
}

W::IMAGE_OPTIONAL_HEADER32& PEFile32::opt_header() const
{
	auto opt_header_ptr = reinterpret_cast<W::PIMAGE_OPTIONAL_HEADER32>(m_view
		+ dos_header().e_lfanew + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER));
	return *opt_header_ptr;
}

void PEFile32::fix_image_base(W::DWORD newBaseAddress)
{
	auto& header = this->opt_header();
	VERBOSE("Fix PE Dump", "Modifying base address from %x to %x", header.ImageBase, newBaseAddress);
	header.ImageBase = newBaseAddress;
}

void PEFile32::fix_alignment()
{
	auto& header = this->opt_header();
	VERBOSE("Fix PE Dump", "Modifying file alignment from %x to %x", header.FileAlignment, header.SectionAlignment);
	header.FileAlignment = header.SectionAlignment;
}

void PEFile32::fix_sections()
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

void PEFile32::fix_reloc_section()
{
	auto headers = this->section_headers();
	for (const auto header : headers)
	{
		if (!strcmp ((const char *)header->Name, ".reloc")) {
			header->SizeOfRawData = 0;
			VERBOSE("Fix PE Dump", "Modified size of .reloc section to 0");
			return;
		}
	}
}


size_t PEFile32::headers_size() const
{
	return sizeof(W::IMAGE_DOS_HEADER) + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER) + sizeof(W::IMAGE_OPTIONAL_HEADER32);
}