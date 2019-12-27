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
//
int mixTable[] = {0x02,0x03,0x01,0x01,0x01,0x02,0x03,0x01,0x01,0x01,0x02,0x03,0x03,0x01,0x01,0x02};

void RotByte(){
	unsigned char zero = CurrentKey[0];
	for (int a = 0; a < 4; a++){
		if (a!= 3)
			CurrentKey[a] = CurrentKey[a+1];
		else
			CurrentKey[a] = zero;
	}
}

void SubByte(){
	for (int i = 0; i < 4; i++){
		CurrentKey[i] = SBox[CurrentKey[i]];
	}
}

void SubBytes(){
	for (int i = 0; i < 4; i++){
		for (int j=0;j<4;j++){
			state[i][j]=SBox[state[i][j]];
		}
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
				printf("\n"); // �L�X44��ExpandKey (11��RoundKey) 
		}
		printf("\n");
	}	

}

void AddRoundKey(int round)
{
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= ExpandKey[(i * 4 + j) + (round * 4 * 4)]; 
}

// left Circular Shift (row), �C������
void ShiftRows(){
    unsigned char temp;
    
    //�ĤG��洫�@��(ROL 1) 
    temp    	= state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

	//�ĤT��洫���(ROR 2) 
    temp    	= state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp        = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

	//�ĥ|��洫�T��(ROR 1) 
    temp        = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

void MixColumns(){
	//�ؤ@��mixTable , ��mixcolumns�C�@��ƭȪ��B�z�覡 
	unsigned char temp,temp2,temp3,t,sum;
	for(int i=0;i<4;i++){
		temp3 = state[0][i];
		//sum���Ӧ������XOR�A�]����C�@�檺�B�z�Ҭ����F�ۨ����~��L3�檺XOR�A�U�γo�ؤ覡�x�s��� 
		sum = state[0][i]^state[1][i]^state[2][i]^state[3][i];
		
		temp  = state[0][i] * mixTable[4*i+0];
		temp2 = state[1][i] * mixTable[4*i+1];
		t = sum^state[0][i];
		state[0][i] = temp^temp2^t;
		
		temp  = state[1][i] * mixTable[4*i+1];
		temp2 = state[2][i] * mixTable[4*i+2];
		t = sum^state[1][i];
		state[1][i] = temp^temp2^t;
		
		temp  = state[2][i] * mixTable[4*i+2];
		temp2 = state[3][i] * mixTable[4*i+3];
		t = sum^state[2][i];
		state[2][i] = temp^temp2^t;
		
		temp  = state[3][i] * mixTable[4*i+3];
		temp2 = temp3 * mixTable[4*i+0];
		t = sum^state[3][i];
		state[3][i] = temp^temp2^t;
				
	}
	
}

int main(){
	
	FILE *pw,*ot;
	
	srand(time(NULL));
	
	printf("select AES type: AES-128 / AES-192 / AES-256 => AES-");
	scanf("%d", &AESOption);
	//�Ȯɥγo�ؤ覡��ȡA��ɭԬݭn���n�����ǤJ�^�X��
	nk = AESOption / 32;
	nr = AESOption / 32 + 7;
		
	
	printf("select mode: (1) random key / (2) custom key => ");
	scanf("%d", &ModeOption);
	
	if (ModeOption == 2){
		printf("AES-%d mode: enter %d words =>", AESOption, AESOption / 8);
		scanf("%s", CipherKey);
	}
	else{
		//printf("CipherKey is: ");//�P�ϥΪ̤��� 
	}
	
	
	
	printf("PlainText : ");
	
	
	scanf("%s", &plainText);
	if(strlen((const char*)plainText)<16){
		printf("%d\n",strlen((const char*)plainText));
		for(int i=strlen((const char*)plainText);i<16;i++){
			plainText[i] = '0';
		}
	}
	for(int i=0;i<4;i++){
		for(int j=0;j<4;j++){
			state[j][i] = plainText[i*4+j];
		}
	}
	printf("plainTextLen : %d\n",strlen((const char*)plainText));
	printf("plainText :");
	
	for(int i=0;i<16;i++){
		printf("%c",plainText[i]);
	}
	printf("\n");
	
	
	pw = fopen("password.txt","wb");
	for(int c = 0; c < AESOption / 8; c++){
		if (ModeOption == 1)
			CipherKey [c] = (char)(rand() % 256);

		printf("%02X ", CipherKey[c]); // �L�XCipherKey 
		block [c] = (unsigned char) CipherKey[c];
		fprintf(pw, "%c", CipherKey[c]);
	}
	printf("\n");
	
	memcpy(ExpandKey, block, sizeof(block));
	
	KeyExpansion();
	
	
	
    int round = 0;
    // round 0 : add round key, ��0�^�X: �Ȱ���-key XOR block - key�ϥ�[w0 ~ w3]
    AddRoundKey(round);

    // Round 1 ~ Nr-1, ���а��� 1 ~ Nr-1�^�X
     
    for (round = 1;round < nr;round++){
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }
	
    // Round Nr, no MixColumns(), �� Nr �^�X �S���V�X��B��
    SubBytes();
    ShiftRows();
    AddRoundKey(nr);

    /*
     *  �Nstate[] transform �� out[]�W
     *  �ϥ�:
     *   [c0 c4 c8  c12
     *    c1 c5 c9  c13    --> [c0 c1 c2 ... c15]
     *    c2 c6 c10 c14
     *    c3 c7 c11 c15]
     */
     
    for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            out[i * 4 + j]=state[j][i];
            
    ot = fopen("out.txt","wb");
    for(int i=0;i<16;i++){
    	fprintf(ot,"%c",out[i]);
	}
	 
	system("pause");
}
