#include "interpreter.h"
#include <stdint.h>

//function declarations
int sizeOfInstruction(uint8_t opcode);
unsigned char reverse(uint8_t b);
void interpretByteArray(uint8_t *byteArray);

int main()
{
    FILE *fp = fopen(FILE_NAME, "rb");
    if (fp == NULL)
    {
        exit(1);
    }

    /*
     * read in the number of bytes and store them into a byte array
     */
    fseek(fp, 0, SEEK_END); //move the file pointer to the end of the file
    long numberOfBytes = ftell(fp); //save the number of bytes
    fseek(fp, 0, SEEK_SET); //move the file pointer back to the beginning of the file
    uint8_t *byteArray = malloc(numberOfBytes * sizeof(uint8_t)); //create the byte array
    if (byteArray == NULL)
    {
        exit(1);
    }

    //read in the bytes and place them in the byte array
    int i = 0;
    while (!feof(fp))
    {
        fread(&byteArray[i], sizeof(uint8_t),1, fp);
        i++;
    }
    fclose(fp);
    fp = NULL;

    //function calls
    interpretByteArray(byteArray);
    free(byteArray);
    return 0;
}

//used a function to receive the correct instruction length
int sizeOfInstruction(uint8_t opcode)
{
    switch(opcode)
    {
        case END:
        {
            return END_SIZE;
        }
        case JMP:
        {
            return JMP_SIZE;
        }
        case SWP:
        {
            return SWP_SIZE;
        }
        case ADD:
        {
            return ADD_SIZE;
        }
        case XOR:
        {
            return XOR_SIZE;
        }
        case INVERT:
        {
            return INVERT_SIZE;
        }
        case PRINT:
        {
            return PRINT_SIZE;
        }
        default:
        {
            printf("%s", "unknown opcode");
            break;
        }
    }
    return 0;
}

/*
 * function to reverse the bits of a byte.
 * First the left four bits are swapped with the right four bits.
 * Then all adjacent pairs are swapped and then all adjacent single bits.
 * This results in a reversed order.
 */
 uint8_t reverse(uint8_t b) {
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}
void interpretByteArray(uint8_t *byteArray)
{
    int currentInstruction = 0;    //initialize current instruction

    while (1)
    {
        uint8_t opcode = byteArray[currentInstruction]; //initialize opcode
        int instructionLength = sizeOfInstruction(opcode); //retrieve the size of the instruction

        switch (opcode)
        {
            case END:
            {
                return;
            }
            case JMP:
            {
                //save the offset as a signed int and move the current instruction
                int16_t offset = *(int16_t *)(byteArray + currentInstruction + 1); //cast the value as a signed integer
                currentInstruction += offset;
                break;
            }
            case SWP:
            {
                //swap the values at both indexes given
                uint8_t index1 = byteArray[currentInstruction+1]; //save the value of index1
                uint8_t index2 = byteArray[currentInstruction+2]; //save the value of index2
                uint8_t tmp = byteArray[index1]; //save the value of byte array at index1 to a tmp variable
                byteArray[index1] = byteArray[index2]; //set the value at index 1 equal to the value at index2
                byteArray[index2] = tmp; //set the value at index2 equal to the original value at index1
                currentInstruction += instructionLength;
                break;
            }
            case ADD:
            {
                //Add a constant unsigned int to the 4 bytes at the given byte index.
                uint8_t index = byteArray[currentInstruction+1];
                uint32_t adding = *(uint32_t *)(byteArray+currentInstruction+2); //cast the value to an unsigned integer
                *(uint32_t *)(byteArray + index) += adding; //add the value at the index indicated
                currentInstruction += instructionLength;
                break;
            }
            case XOR:
            {
                //Xor a constant long long to the 8 bytes at the given byte index.
                uint8_t index = byteArray[currentInstruction + 1];
                uint64_t xoring = *((uint64_t *)(byteArray + currentInstruction + 2)); //cast the value to a long long integer
                *((uint64_t *)(byteArray + index)) ^= xoring; //xor the value to the 8 bytes at the given byte index
                currentInstruction += instructionLength;
                break;
            }
            case INVERT:
            {
                //reverse the order of the bits at the given index
                uint8_t index = byteArray[currentInstruction+1]; //
                byteArray[index] = reverse(byteArray[index]); //reverse the bits of the byte 
                currentInstruction += instructionLength;
                break;
            }
            case PRINT:
            {
                //print the character given
                uint8_t asciiChar = byteArray[currentInstruction+1];
                printf("%c", asciiChar);
                currentInstruction += instructionLength;
                break;
            }
            default:
            {
                fprintf(stderr, "\nError: Invalid opcode %02x at instruction %d\n", opcode, currentInstruction);
                return;
            }
        }
    }
}
