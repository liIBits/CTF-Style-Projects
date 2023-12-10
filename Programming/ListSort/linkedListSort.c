//
// Created by Michael Mendoza on 8/18/22.
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Node Structure */
typedef struct node
{
    uint16_t value;
    uint16_t length;
    struct node *flink;
    struct node *blink;
    char *flag;
}NODE;

/* Function Declarations */

void print(NODE *node);
void xor(NODE *node, int maxLength);
void freeLinkedListNodes(NODE *node);

int main()
{

    /*
     * open the file to read in the nodes for a linked list
    */
    FILE *fp = fopen("input_stream.bin", "rb");
    if (fp == NULL)
    {
        perror ("Error in opening the file.");
        return (-1);
    }


    //initializing variables
    NODE *head = NULL, *tail = NULL;    //included the tail node since this is a doubly linked list
    int maxLength = 0;                  //this is the max length of the flag piece that will be read in

    while(1)
    {
        //allocating space for a new Node to be read-in
        NODE *newNode = (NODE *)malloc(sizeof(NODE));
        if (newNode == NULL)
        {
            exit(3);
        }

        //reading in the Node from the file and finding the max length of the flag pieces
        fread(&newNode->flink, sizeof(uint16_t), 1, fp);
        fread(&newNode->value, sizeof(uint16_t), 1, fp);
        fread(&newNode->length, sizeof(uint16_t), 1, fp);
        if (newNode->length > maxLength)
        {
            maxLength = newNode->length;
        }

        //the current length is used to allocate memory for the flag piece
        newNode->flag = (char *) malloc(newNode->length * sizeof(char));
        if(newNode->flag == NULL)
        {
            exit(2);
        }

        //once memory is allocated, read in the data from the file
        fread(newNode->flag, (newNode->length) * sizeof(char), 1, fp);



        //initializing the linked list
        if (head == NULL)
        {
            head = newNode;
            tail = newNode;
            head->flink = NULL;
            head->blink = NULL;
        }
        else
        {
            /*
             * smallest node value is going to be the head, so we check to see
             * if the new node is smaller than the head value, and if it is we
             * insert the node before the head value
             */
            if(newNode->value < head->value)
            {
                head->blink = newNode;
                newNode->flink = head;
                head = newNode;
            }

            else
            {
                //create a node to traverse through the list
                NODE *currentNode = head;

                /*
                 * check to see if there is only one node, if there are no other nodes
                 * in the list then the new node is the 2nd node and is initialized as such
                */
                if(head->flink == NULL)
                {
                    newNode->blink = head;
                    head->flink = newNode;
                    tail = newNode;
                    newNode->flink = NULL;
                }

                //if there's more than 2 node in the linked list
                else
                {
                    /*
                     * traverse through the list until you reach a node whose value
                     * is greater than the new node and insert the node behind it
                     */
                    while (currentNode->flink != NULL && currentNode->flink->value < newNode->value)
                    {
                        currentNode = currentNode->flink;
                    }
                    newNode->flink = currentNode->flink;
                    newNode->blink = currentNode;
                    currentNode->flink = newNode;
                }

                /*
                 * to set the blink correctly, set the current node equal to the next
                 * node and then set the blink equal to the new node. Then you can also
                 * determine if the current node is the last node of the list.
                 */
                if(newNode->flink != NULL)
                {
                    currentNode = newNode->flink;
                    currentNode->blink = newNode;
                    if(currentNode->flink == NULL)
                    {
                        tail = currentNode;
                    }
                }
            }
        }
        //exit the while loop once the end of the file is reached
        if(feof(fp))
        {
            break;
        }
    }

    //close the file
    fclose(fp);
    fp = NULL;

    //function calls
    //print(head);
    xor(head, maxLength);       //xor's and prints the flag
    freeLinkedListNodes(head);

    return 0;
}

void print(NODE *node)
{
    //traverse through the list and print the nodes
    for (; node != NULL; node = node->flink)
    {
        printf("%p %p %p %d %d %s\n", node->blink, node, node->flink, node->value, node->length, node->flag);
    }
}

void xor(NODE *node, int maxLength)
{
    //created a node to traverse through the list
    NODE *current = node;

    /*
     * initialized the flag array to 0 with the size of the maximum sized flag piece
     * this allows the flag pieces to xor the flag array with no issues. 0 ^ anyChar = anyChar.
     */
    char *flagArray = (char *)calloc(maxLength, sizeof(char));
    if(flagArray == NULL)
    {
        exit(4);
    }


    while(current != NULL)
    {
        //iterate over even indexes
        if(current->value % 2 == 0)
        {
            //xor flag array with the flag piece up to the length of the current flag piece
            for (int i = 0; i < current->length; i++)
            {
                flagArray[i] ^= current->flag[i];
            }
        }
        current = current->flink;
    }
    printf("\n%s\n", flagArray);
    free(flagArray);
}

void freeLinkedListNodes(NODE *node)
{
    //create a tmp node to free memory while traversing through the list
    NODE *tmp = NULL;

    while(node != NULL)
    {
        tmp = node;
        node = node->flink;
        free(tmp->flag);
        free(tmp);
    }
}
