#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


//create a struct for each element in the array
typedef struct element
{
    uint16_t value;
    uint8_t flagPiece[13];
}element;

//function declaration
int cmpfunc (element *a, element *b);

int main()
{
    //create the file pointer to read in the data
    FILE *fp = fopen("./input_stream.bin", "rb");
    if(fp == NULL)
    {
        exit(1);
    }

    /* move the file pointer to the end of the file,
     * save the total bytes of the file and set the
     * file pointer back to the beginning of the file
     */
    fseek(fp, 0, SEEK_END);
    long numberOfBytes = ftell(fp);
    rewind(fp);

    //save the number of elements
    int numberOfElements = numberOfBytes / 15;

    //allocate memory for and create the array of elements
    element *arrayOfElements = (element *)malloc(numberOfBytes);
    if(arrayOfElements == NULL)
    {
        exit(1);
    }

    //read in the data to the array
    for(int i=0; i < numberOfElements; i++)
    {
        fread(&arrayOfElements[i].value, sizeof(uint16_t), 1, fp);
        fread(&arrayOfElements[i].flagPiece, sizeof(uint8_t), 13, fp);
    }
    fclose(fp);
    fp = NULL;

    //sort the elements using qsort()
    qsort(arrayOfElements, numberOfElements, sizeof(element), cmpfunc); //cmpfunc is changed to accommodate the struct

    //allocate memory for and initialize the flag with 0's
    char *flag = calloc(13, sizeof(char));
    if(flag == NULL)
    {
        exit(1);
    }

    //perform xoring with even indexes of "ArrayOfElements"
    for (int i = 0; i < numberOfElements; i+=2)
    {
        for (int j = 0; j < 13; j++)
        {
            flag[j] ^= arrayOfElements[i].flagPiece[j];
        }
    }

    //test to see if the array is sorted
//    for (i = 0; i < numberOfElements; i++)
//    {
//        printf("%d %s\n", arrayOfElements[i].value, arrayOfElements[i].flagPiece);
//    }
    printf("%s\n", flag);
    
    free(arrayOfElements);
    free(flag);
}

//this function is utilized in qsort(),
//It was modified to take in 2 elements and compare their values
int cmpfunc (element *a, element *b)
{
    return (a->value - b->value );
}
