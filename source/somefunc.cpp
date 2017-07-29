unsigned long long strlen_unsigned(const unsigned char * buffer){
   unsigned long long result = 0;
   while(*buffer++) result++;
   return result;
}
