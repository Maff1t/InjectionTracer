#pragma once
#include <string>
#include <vector>

#include "Utils.h"

namespace W {
#include "Windows.h"
#include "minwindef.h"
#include "psapi.h"
#include "winbase.h"
}

using std::vector;
using std::string;

constexpr size_t NT_SIGNATURE_SIZE = 4;

class PEFile
{
public:
	virtual ~PEFile();

	W::IMAGE_DOS_HEADER& dos_header() const;
	W::IMAGE_FILE_HEADER& pe_header() const;
	vector<W::PIMAGE_SECTION_HEADER> section_headers() const;

	W::DWORD size() const;
	virtual bool is_file_valid() const;
	void write_to_file(const std::string& _filename) const;

protected:
	W::HANDLE m_mapping{ nullptr };
	unsigned char* m_view{ nullptr };
	W::DWORD m_size{ 0 };

	bool init_mapping_view(const std::string& _filename);
	virtual std::size_t headers_size() const = 0;
};