#pragma once
#include "PEFile.h"
#include "Utils.h"

namespace W {
#include "Windows.h"
#include "minwindef.h"
#include "psapi.h"
#include "winbase.h"
}

class PEFile32 : public PeFile
{
public:
	PEFile32(const std::string& _filename);

	// This type cannot be copied, to avoid double-freeing HANDLEs use move operator/ctor
	PEFile32() = default;
	PEFile32(PEFile32&& _other) = default;
	PEFile32(const PEFile32& _other) = delete;

	W::IMAGE_OPTIONAL_HEADER32& opt_header() const;

	PEFile32& operator=(const PEFile32& _other) = delete;
	PEFile32& operator=(PEFile32&& _other) = default;

	void fixBaseAddress(W::DWORD newBaseAddress);
	void fixAlign();
	void fixSections();
	void fixRelocSection();
	void disableASLR();

private:
	virtual size_t headers_size() const final;
};