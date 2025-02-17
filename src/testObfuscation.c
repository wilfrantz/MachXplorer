#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/// Dummy encrypted data
unsigned char encryptedData[] = {0x89, 0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78};

/// Function that will be called indirectly
void secretFunction()
{
	printf("Executing secret function!\n");
}

/// Function pointer (for indirect call simulation)
void (*indirectCall)(void);

int main()
{
	printf("Starting test binary...\n");

	// Direct function call (normal execution)**
	secretFunction();

	// Indirect function call (simulates obfuscation)**
	indirectCall = &secretFunction;
	indirectCall();

	// Junk code (NOP sled)**
	asm volatile(
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t"
		"nop\n\t");

	// Dynamic function resolution (dlopen, dlsym)**
	void *handle = dlopen("libc.dylib", RTLD_LAZY);
	if (handle)
	{
		void (*putsFunc)(const char *) = (void (*)(const char *))dlsym(handle, "puts");
		if (putsFunc)
		{
			putsFunc("Dynamically resolved puts function!\n");
		}
		dlclose(handle);
	}

	// Simulated "encrypted" function (data XOR encoded)**
	for (size_t i = 0; i < sizeof(encryptedData); i++)
	{
		encryptedData[i] ^= 0xAA; // XOR encode
	}

	printf("Test binary execution completed.\n");
	return 0;
}
