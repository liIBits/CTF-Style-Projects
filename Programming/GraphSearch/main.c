#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Structure to represent a node in the graph
typedef struct Node
{
    char val;
    uint16_t length;
    uint16_t *out;
} Node;

//function declaration
int search(Node** nodes, int current, char* flag, int flagIndex);
void free_nodes(Node** node, int num_nodes);

int main() {
    // Open the binary file for reading and parse the graph data
    FILE *fp = fopen("input_stream.bin", "rb");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }
    // Create an array matrix to store the nodes of the graph and create an adjacency list
    Node **nodes = (Node **)malloc(sizeof(Node *));
    if(nodes == NULL)
    {
        exit(1);
    }
    int num_nodes = 0;

    // Read the file until the end is reached
    while (!feof(fp)) {

        //create a new node to be read in
        Node *newNode = (Node *)malloc(sizeof(Node));
        if(newNode == NULL)
        {
            exit(1);
        }

        //increase the size of nodes to accommodate an extra row of nodes
        nodes = realloc(nodes, (num_nodes + 1) * sizeof(Node)); //num_nodes + 1 is the amount of rows in the matrix
        if (nodes == NULL)
        {
            exit(1);
        }
        nodes[num_nodes] = newNode; //placing the address of the new node in the matrix
        num_nodes++; //now increasing the size to account for the actual number of nodes in the matrix

        //Read the val and length values from the file
        fread(&newNode->val, sizeof(uint8_t), 1, fp);
        fread(&newNode->length, sizeof(uint16_t), 1, fp);

        // Read the out values from the file
        newNode->out = (uint16_t *) malloc(newNode->length * sizeof(uint16_t)); //allocate memory for all the out nodes
        if(newNode->out == NULL)
        {
            exit(1);
        }
        for (int i = 0; i < newNode->length; i++)
        {
            fread(&newNode->out[i], sizeof(uint16_t) , 1, fp); //read in all the neighbors
        }
    }
    fclose(fp);
    fp = NULL;


    //allocate memory for the flag
    char *flag = (char*) malloc(num_nodes * sizeof(char));
    {
        if(flag == NULL)
        {
            exit(1);
        }
    }

    //start the search for the flag
    search(nodes, 0, flag, 0);

    //freeing the allocated memory
    free_nodes(nodes, num_nodes);
    free(flag);

    return 0;
}

//recursive function to find and print the flag
int search(Node** nodes, int current, char* flag, int flagIndex)
{
    //the first and last iteration will automatically be saved
    flag[flagIndex] = nodes[current]->val;

    //check to see if current node has the char value we need
    if (nodes[current]->val == '}')
    {
        flag[flagIndex+1] = '\0';
        printf("Flag: %s\n", flag);
        return 1;
    }


    //recursively go through all the neighbor nodes
    //NOTE: Out refers to the destination node by index within the adjacency list
    for (int i = 0; i < nodes[current]->length; i++) {
        if (search(nodes, nodes[current]->out[i], flag, flagIndex + 1)) {
            return 1;
        }
    }
    return 0;
}

//function to free the nodes in the adjacency list
void free_nodes(Node** nodes, int num_nodes)
{
    //iterate over every node in the graph
    for (int i = 0; i < num_nodes; i++)
    {
        //free each nodes out pointer as well as the current node
        free(nodes[i]->out);
        free(nodes[i]);
    }

    //finally, free the double pointer
    free(nodes);
}




