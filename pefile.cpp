#include "pefile.h"

void PeFile::init_mapping_view(const std::string& _filename)
{
	W::HANDLE hfile = W::CreateFileA(_filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hfile == (W::HANDLE)-1)
		ERROR ("Could not open file %s", _filename.c_str());

	size_t last_slash_idx = _filename.find_last_of("\\");;
	string name;
	if (last_slash_idx != string::npos)
	{
		name = _filename.substr(last_slash_idx);
	}
	else
	{
		name = _filename;
	}
	m_size = W::GetFileSize(hfile, NULL);
	if (m_size == (W::DWORD)0xFFFFFFFF)
	{
		W::CloseHandle(hfile);
		ERROR("Could not get size of file, is it over 4 GiB?");
	}
	m_mapping = W::CreateFileMappingA(hfile, NULL, PAGE_READONLY, 0, 0, name.c_str());
	W::CloseHandle(hfile);
	if (!m_mapping)
		ERROR("Could not map file to memory");
	// CoW mapping view
	void* view = W::MapViewOfFile(m_mapping, FILE_MAP_COPY, 0, 0, 0);
	if (!view)
		ERROR("Could not create file mapping view");
	
	m_view = static_cast<unsigned char*>(view);
}

W::IMAGE_DOS_HEADER& PeFile::dos_header() const
{
	W::PIMAGE_DOS_HEADER dos_header_ptr = reinterpret_cast<W::PIMAGE_DOS_HEADER>(m_view);
	return *dos_header_ptr;
}

W::IMAGE_FILE_HEADER& PeFile::pe_header() const
{
	auto dos_header = this->dos_header();
	auto pe_header_ptr = reinterpret_cast<W::PIMAGE_FILE_HEADER>(m_view + dos_header.e_lfanew + NT_SIGNATURE_SIZE);
	return *pe_header_ptr;
}

vector<W::PIMAGE_SECTION_HEADER> PeFile::section_headers() const
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

W::DWORD PeFile::size() const
{
	return m_size;
}

bool PeFile::is_file_valid() const
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

PeFile::~PeFile()
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