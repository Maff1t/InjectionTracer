#pragma once
#include "PEFile.h"

class PEFile64 : public PEFile
{
public:
	PEFile64(const std::string& _filename);

	// This type cannot be copied, to avoid double-freeing HANDLEs use move operator/ctor
	PEFile64() = default;
	PEFile64(PEFile64&& _other) noexcept = default;
	PEFile64(const PEFile64& _other) noexcept = delete;

	W::IMAGE_OPTIONAL_HEADER64& opt_header() const;

	PEFile64& operator=(const PEFile64& _other) = delete;
	PEFile64& operator=(PEFile64&& _other) noexcept = default;

	bool isValidPe64();
	void fixBaseAddress(W::LPVOID newBaseAddress);
	void fixAlign();
	void fixSections();
	void fixRelocSection();
	void disableASLR();


private:
	virtual std::size_t headers_size() const noexcept final;
};