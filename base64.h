#ifndef _BASE64_H
#define _BASE64_H

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

int base64_decode_value(signed char value_in);
void base64_init_decodestate(struct base64_decodestate *state_in);
size_t base64_decode_block(const char *code_in, size_t length_in, char *plaintext_out, size_t plaintext_outl, struct base64_decodestate *state_in);
void base64_init_encodestate(struct base64_encodestate *state_in);
char base64_encode_value(char value_in);
size_t base64_encode_block(const char *plaintext_in, size_t length_in, char *code_out, struct base64_encodestate *state_in);
size_t base64_encode_blockend(char *code_out, struct base64_encodestate *state_in);

size_t base64_decode(char *output, size_t outputl, const char *input, size_t inputl);
size_t base64_encode(char *output, const char *input, size_t inputl);

#endif
