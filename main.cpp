#include <iostream>
#include "Platform/platform.h"

using namespace std;

int main() {
    cout << "Hello world!" << endl;
    string hostname = "0.0.0.0";
    createServer(3000,hostname);
    return 0;
}