/*
 * base64.c: libb64 compressed code. Public domain.
 * See http://libb64.sourceforge.net/ for original code and infos.
 *
 * Modified and fixed by Lynx <lynx@lynxlynx.ru> 03Jun2016:
 * - Single TU, minimal external dependencies
 * - Stream operation, no newline insertions
 * - Fixed code style to pure K&R
 * - Fixed integer overflows and fixed size types
 * - Fixed out of bounds access in base64_decode_block 
 * - Force specify output size for output buffer when decoding
 * - Fixed signed/unsigned issue on ARM
 * - Added generic memory converter wrappers which do not expose internals
 * - All functions calculate number of processed characters and return them to caller
 */

#include <string.h>
#include <stdlib.h>

enum base64_decodestep {
	estep_a, estep_b, estep_c, estep_d
};

struct base64_decodestate {
	enum base64_decodestep step;
	char plainchar;
	size_t count;
};

enum base64_encodestep {
	dstep_a, dstep_b, dstep_c
};

struct base64_encodestate {
	enum base64_encodestep step;
	char result;
	size_t count;
};

int base64_decode_value(signed char value_in)
{
	static const signed char decoding[] = {
		62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1,
		-1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
		21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
		35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
	};
	static const char decoding_size = sizeof(decoding);
	if (value_in < 43) return -1;
	value_in -= 43;
	if (value_in >= decoding_size) return -1;
	return decoding[(int)value_in];
}

void base64_init_decodestate(struct base64_decodestate *state_in)
{
	state_in->step = estep_a;
	state_in->plainchar = 0;
	state_in->count = 0;
}

#define CHECK_BOUNDS do { if (plainchar-plaintext_out >= plaintext_outl) goto _ret; } while (0)

size_t base64_decode_block(const char *code_in, size_t length_in, char *plaintext_out, size_t plaintext_outl, struct base64_decodestate *state_in)
{
	const char *codechar = code_in;
	char *plainchar = plaintext_out;
	int fragment;
	
	*plainchar = state_in->plainchar;
	
	switch (state_in->step) {
		while (1) {
			case estep_a:
					do {
						if (codechar == code_in+length_in) {
							state_in->step = estep_a;
							state_in->plainchar = *plainchar;
							state_in->count += (plainchar - plaintext_out);
							return plainchar - plaintext_out;
						}
						fragment = base64_decode_value(*codechar++);
					} while (fragment < 0);
					*plainchar = (fragment & 0x3f) << 2;
			case estep_b:
					do {
						if (codechar == code_in+length_in) {
							state_in->step = estep_b;
							state_in->plainchar = *plainchar;
							state_in->count += (plainchar - plaintext_out);
							return plainchar - plaintext_out;
						}
						fragment = base64_decode_value(*codechar++);
					} while (fragment < 0);
					*plainchar++ |= (fragment & 0x30) >> 4;
					CHECK_BOUNDS;
					*plainchar = (fragment & 0x0f) << 4;
			case estep_c:
					do {
						if (codechar == code_in+length_in) {
							state_in->step = estep_c;
							state_in->plainchar = *plainchar;
							state_in->count += (plainchar - plaintext_out);
							return plainchar - plaintext_out;
						}
						fragment = base64_decode_value(*codechar++);
					} while (fragment < 0);
					*plainchar++ |= (fragment & 0x3c) >> 2;
					CHECK_BOUNDS;
					*plainchar = (fragment & 0x03) << 6;
			case estep_d:
					do {
						if (codechar == code_in+length_in) {
							state_in->step = estep_d;
							state_in->plainchar = *plainchar;
							state_in->count += (plainchar - plaintext_out);
							return plainchar - plaintext_out;
						}
						fragment = base64_decode_value(*codechar++);
					} while (fragment < 0);
					*plainchar++ |= (fragment & 0x3f);
		}
	}

_ret:	state_in->count += (plainchar - plaintext_out);
	return plainchar - plaintext_out;
}

void base64_init_encodestate(struct base64_encodestate *state_in)
{
	state_in->step = dstep_a;
	state_in->result = 0;
	state_in->count = 0;
}

char base64_encode_value(char value_in)
{
	static const char *encoding = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (value_in > 63) return '=';
	return encoding[(int)value_in];
}

size_t base64_encode_block(const char *plaintext_in, size_t length_in, char *code_out, struct base64_encodestate *state_in)
{
	const char *plainchar = plaintext_in;
	const char *const plaintextend = plaintext_in + length_in;
	char *codechar = code_out;
	char result;
	char fragment;
	
	result = state_in->result;
	
	switch (state_in->step) {
		while (1) {
			case dstep_a:
					if (plainchar == plaintextend) {
						state_in->result = result;
						state_in->step = dstep_a;
						state_in->count += (codechar - code_out);
						return codechar - code_out;
					}
					fragment = *plainchar++;
					result = (fragment & 0xfc) >> 2;
					*codechar++ = base64_encode_value(result);
					result = (fragment & 0x03) << 4;
			case dstep_b:
					if (plainchar == plaintextend) {
						state_in->result = result;
						state_in->step = dstep_b;
						state_in->count += (codechar - code_out);
						return codechar - code_out;
					}
					fragment = *plainchar++;
					result |= (fragment & 0xf0) >> 4;
					*codechar++ = base64_encode_value(result);
					result = (fragment & 0x0f) << 2;
			case dstep_c:
					if (plainchar == plaintextend) {
						state_in->result = result;
						state_in->step = dstep_c;
						state_in->count += (codechar - code_out);
						return codechar - code_out;
					}
					fragment = *plainchar++;
					result |= (fragment & 0xc0) >> 6;
					*codechar++ = base64_encode_value(result);
					result  = (fragment & 0x3f) >> 0;
					*codechar++ = base64_encode_value(result);
		}
	}
	/* control should not reach here */
	state_in->count += (codechar - code_out);
	return codechar - code_out;
}

size_t base64_encode_blockend(char *code_out, struct base64_encodestate *state_in)
{
	char *codechar = code_out + state_in->count;
	
	switch (state_in->step) {
		case dstep_b:
			*codechar++ = base64_encode_value(state_in->result);
			*codechar++ = '=';
			*codechar++ = '=';
			state_in->count += 3;
			break;
		case dstep_c:
			*codechar++ = base64_encode_value(state_in->result);
			*codechar++ = '=';
			state_in->count += 2;
			break;
		case dstep_a:
			break;
	}

	return codechar - code_out;
}

/* Process single block of memory */
size_t base64_decode(char *output, size_t outputl, const char *input, size_t inputl)
{
	struct base64_decodestate dstate;
	size_t r;

	base64_init_decodestate(&dstate);
	base64_decode_block(input, inputl, output, outputl, &dstate);

	r = dstate.count;
	memset(&dstate, 0, sizeof(struct base64_decodestate));

	return r;
}

size_t base64_encode(char *output, const char *input, size_t inputl)
{
	struct base64_encodestate estate;
	size_t r;

	base64_init_encodestate(&estate);
	base64_encode_block(input, inputl, output, &estate);
	base64_encode_blockend(output, &estate);

	r = estate.count;
	memset(&estate, 0, sizeof(struct base64_encodestate));

	return r;
}
