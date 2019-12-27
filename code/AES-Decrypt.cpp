#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 

unsigned char block [32], ExpandKey [240], CurrentKey[4], InputCipher[32], CipherKey [32],state[4][4],out[16];
char plainText[128];
int Rcon = 1, nk, nr, RKeyNum = 4, AESOption, ModeOption;

int SBox []= {99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
  	118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
  	147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
  	7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
  	47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
  	251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
  	188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
  	100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
  	50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
  	78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
  	116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
  	158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
  	137,13,191,230,66,104,65,153,45,15,176,84,187,22};

/* Inverse S-box */
int SBox_Inv[256] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d 
};

int mixTable_Inv[] = {14,11,13,9,9,14,11,13,13,9,14,11,11,13,9,14};

void AddRoundKey(int round)
{
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= ExpandKey[(i * 4 + j) + (round * 4 * 4)]; 
}

void SubByte(){
	for (int i = 0; i < 4; i++){
		CurrentKey[i] = SBox[CurrentKey[i]];
	}
}

void SubBytes_Inv(){
	for (int i = 0; i < 4; i++){
		for (int j=0;j<4;j++){
			state[i][j]=SBox_Inv[state[i][j]];
		}
	}
}

void RotByte(){
	unsigned char zero = CurrentKey[0];
	for (int a = 0; a < 4; a++){
		if (a!= 3)
			CurrentKey[a] = CurrentKey[a+1];
		else
			CurrentKey[a] = zero;
	}
}

void KeyExpansion(){	
	for (RKeyNum = nk; RKeyNum < 4 * nr; RKeyNum++){
		for (int e = 0; e < 4; e++){
			CurrentKey [e] = ExpandKey [4 * RKeyNum - 4 + e];
		}
		if (RKeyNum % nk == 0){
			RotByte();
			SubByte();
			CurrentKey[0] ^= Rcon;
			if (Rcon < 128)
				Rcon *= 2;
			else
				Rcon = 27;
		
		}
		else if (nk == 8 && RKeyNum % nk == 4){
			SubByte();
		}
		for (int add = 0; add < 4; add++){
			ExpandKey [4 * RKeyNum + add] = CurrentKey[add] ^ ExpandKey [4 * (RKeyNum - nk) + add];
			if (ExpandKey [4 * RKeyNum + add] > 256){
				ExpandKey [4 * RKeyNum + add] ^= 0x11B;
			}
		}
				
	}
	
	for (int r = 0; r < 11; r++){
		for (int p = 0; p < 16; p++){
			printf("%02X ", ExpandKey [r * 16 + 4 * (p % 4) + (p / 4) % 4]);
			if (p % 4 == 3)
				printf("\n"); // 印出44把ExpandKey (11把RoundKey) 
		}
		printf("\n");
	}	
}





void ShiftRows_Inv(){
    unsigned char temp;
    
    //第二行交換三個(ROR 1) 
    temp    = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    //第三行交換兩個(ROR 2) 
    temp    = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp    = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    //第四行交換一個(ROL 1) 
    temp    = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

void MixColumns_Inv(){
	//建一個mixTableInv , 為每一格數值的處理方式 
	unsigned char temp,temp2,temp3,t,sum;
	for(int i=0;i<4;i++){
		temp3 = state[0][i];
		//sum為該行全部的XOR，因為對每一格的處理皆為除了自身之外其他3格的XOR，顧用這種方式儲存資料 
		sum = state[0][i]^state[1][i]^state[2][i]^state[3][i];
		
		temp  = state[0][i] * mixTable_Inv[4*i+0];
		temp2 = state[1][i] * mixTable_Inv[4*i+1];
		t = sum^state[0][i];
		state[0][i] = temp^temp2^t;
		
		temp  = state[1][i] * mixTable_Inv[4*i+1];
		temp2 = state[2][i] * mixTable_Inv[4*i+2];
		t = sum^state[1][i];
		state[1][i] = temp^temp2^t;
		
		temp  = state[2][i] * mixTable_Inv[4*i+2];
		temp2 = state[3][i] * mixTable_Inv[4*i+3];
		t = sum^state[2][i];
		state[2][i] = temp^temp2^t;
		
		temp  = state[3][i] * mixTable_Inv[4*i+3];
		temp2 = temp3 * mixTable_Inv[4*i+0];
		t = sum^state[3][i];
		state[3][i] = temp^temp2^t;
				
	}
	
}


int main(){
	
	FILE *in,*ot,*password;
	char filename[50];
	
	printf("select AES type: AES-128 / AES-192 / AES-256 => AES-");
	scanf("%d", &AESOption);
	nk = AESOption / 32;
	nr = AESOption / 32 + 7;
	
	printf("Password File Name : ");
	scanf("%s",&filename);
	password = fopen(filename,"rb");
	
	for (int i=0;i<16;i++){
        CipherKey[i] = fgetc(password);
        block [i] = (unsigned char) CipherKey[i];
    }
	memcpy(ExpandKey, block, sizeof(block));
	
	printf("CipherText File Name : ");
	scanf("%s",filename);
	in = fopen(filename,"rb");
	
	for (int i=0;i<16;i++){
        InputCipher[i] = fgetc(in);
    }
    
    
    int round = nr - 1;
    for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			state[j][i] = InputCipher[i*4+j];
		}
	}
    
    AddRoundKey(nr);
    
    for (round=nr-1;round>0;round--){
        ShiftRows_Inv();
        SubBytes_Inv();
        AddRoundKey(round);
        MixColumns_Inv();
    }
    
    ShiftRows_Inv();
    SubBytes_Inv();
    AddRoundKey(0);
    
    for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            out[i * 4 + j]=state[j][i];
    
    ot = fopen("outout.txt","wb");
    for(int i=0;i<16;i++){
    	fprintf(ot,"%c",out[i]);
	}
    
	return 0;
}

