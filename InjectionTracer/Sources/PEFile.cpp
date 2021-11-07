#include "pefile.h"

bool PEFile::init_mapping_view(const std::string& _filename)
{

	W::HANDLE hfile = W::CreateFileA(_filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == (W::HANDLE)-1) {
		ERR("Could not open file %s: %s", _filename.c_str(), GetLastErrorAsString().c_str());
		return false;
	}
	
	m_size = W::GetFileSize(hfile, NULL);
	if (m_size == (W::DWORD)0xFFFFFFFF)
	{
		W::CloseHandle(hfile);
		ERR("Could not get size of file, is it over 4 GiB?");
		return false;
	}
	m_mapping = W::CreateFileMappingA(hfile, NULL, PAGE_READONLY, 0, 0, NULL);
	W::CloseHandle(hfile);
	if (!m_mapping) {
		ERR("Could not map file to memory: %s", GetLastErrorAsString().c_str());
		return false;
	}
	// CoW mapping view
	void* view = W::MapViewOfFile(m_mapping, FILE_MAP_COPY, 0, 0, 0);
	if (!view) {
		ERR("Could not create file mapping view : %s", GetLastErrorAsString().c_str());
		return false;
	}
	m_view = static_cast<unsigned char*>(view);
	return true;
}

W::IMAGE_DOS_HEADER& PEFile::dos_header() const
{
	W::PIMAGE_DOS_HEADER dos_header_ptr = reinterpret_cast<W::PIMAGE_DOS_HEADER>(m_view);
	return *dos_header_ptr;
}

W::IMAGE_FILE_HEADER& PEFile::pe_header() const
{
	auto dos_header = this->dos_header();
	auto pe_header_ptr = reinterpret_cast<W::PIMAGE_FILE_HEADER>(m_view + dos_header.e_lfanew + NT_SIGNATURE_SIZE);
	return *pe_header_ptr;
}

vector<W::PIMAGE_SECTION_HEADER> PEFile::section_headers() const
{
	unsigned section_count = pe_header().NumberOfSections;
	std::vector<W::PIMAGE_SECTION_HEADER> res;
	res.reserve(section_count);

	// Disgusting, I know.
	auto opt_header_size = headers_size() - sizeof(W::IMAGE_DOS_HEADER) - NT_SIGNATURE_SIZE - sizeof(W::IMAGE_FILE_HEADER);
	auto section_headers_base = reinterpret_cast<W::PIMAGE_SECTION_HEADER>(m_view
		+ dos_header().e_lfanew + NT_SIGNATURE_SIZE + sizeof(W::IMAGE_FILE_HEADER)
		+ opt_header_size);
	for (unsigned i = 0; i < section_count; i++)
	{
		auto header = section_headers_base + i;
		res.push_back(header);
	}
	return res;
}

W::DWORD PEFile::size() const
{
	return m_size;
}

bool PEFile::is_file_valid() const
{
	// File should be at least large enough to contain these headers
	if (m_size < headers_size())
		return false;

	// Check MZ + PE header magic
	const auto dos_header = this->dos_header();
	if (dos_header.e_magic != IMAGE_DOS_SIGNATURE || *(W::PDWORD)(m_view + dos_header.e_lfanew) != IMAGE_NT_SIGNATURE)
		return false;

	// Section header count validation
	auto section_count = pe_header().NumberOfSections;
	if (m_size < headers_size() + section_count * sizeof(W::IMAGE_SECTION_HEADER))
		return false;

	return true;
}

PEFile::~PEFile()
{
	if (m_view != nullptr)
	{
		W::UnmapViewOfFile(m_view);
	}
	if (m_mapping != nullptr)
	{
		W::CloseHandle(m_mapping);
	}
}


void PEFile::write_to_file(const std::string& _filename) const
{
	W::HANDLE hfile = W::CreateFileA(_filename.c_str(), GENERIC_WRITE, NULL, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (hfile == (W::HANDLE)-1) {
		ERR("Could not open file %s", _filename.c_str());
	}

	W::DWORD bytes_written{ 0 };
	bool res = W::WriteFile(hfile, m_view, m_size, &bytes_written, NULL);
	W::CloseHandle(hfile);
	
	if (bytes_written != m_size) {
		ERR("Unable to write file");
	}

	VERBOSE("Fix PE Dump", "Written unmapped file at %s", _filename.c_str());
}