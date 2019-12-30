#include<stdio.h>
#include<stdlib.h>
#include<string.h> 
#include<time.h>
unsigned char block [32], ExpandKey [240], CurrentKey[4], InputCipher[32], CipherKey [32], state[4][4], out[16];
char plainText[128];
int Rcon = 1, nk, nr, RKeyNum = 4, AESOption, ModeOption, InputMode,check=1;
	
int SBox[256] =   
{
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  //F
};
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
	
	for (RKeyNum = nk; RKeyNum < 4 * (nr+1); RKeyNum++){
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

void AddRoundKey(int round)
{
    for (int i = 0;i < 4;i++)
        for (int j = 0;j < 4;j++)
            state[j][i] ^= ExpandKey[(i * 4 + j) + (round * 4 * 4)]; 
}

// left Circular Shift (row), 列移位函數
void ShiftRows(){
    unsigned char temp;
    
    //第二行交換一個(ROL 1) 
    temp    	= state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

	//第三行交換兩個(ROR 2) 
    temp    	= state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp        = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

	//第四行交換三個(ROR 1) 
    temp        = state[3][0];
    state[3][0] = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = temp;
}

void MixColumns(){
	unsigned char multi2 [4][4], multi3 [4][4], result[4];
	//建兩個二維陣列，一個用來存放state乘以2(x)的值、另一個存放state乘以3(x+1)的值 
	for (int j = 0; j < 4; j++){
		for (int i = 0; i < 4; i++){
			multi2 [i][j] = state [i][j] * 2;//多項式乘法中，a乘以2 = a乘以x 
			if (state [i][j] * 2 >= 256)
			/*判定乘以2的值是否 >= 256 (x^8), 如果是，則需mod一個不可約分多項式 x^8+x^4+x^3+x+1 (0x11B)，
			這個 "mod" 的動作等同於將乘以2的值 "XOR" 0x11B */ 
				multi2 [i][j] ^= 0x11B;
						
			multi3 [i][j] = multi2[i][j] ^ state [i][j];
			/*由於多項式乘法中，a乘以3 = a乘以x+1，也就是 a乘以2 + a乘以1 => a乘以2 "XOR" a乘以1
			state[i][j]乘以2的值我們剛剛已經算好了，因此直接將這個值去XOR state[i][j]*/	
		}		
	}
	
	for (int j = 0; j < 4; j++){
		for (int i = 0; i < 4; i++){			
			result[i] = multi2[i][j] ^ multi3[(i + 1) % 4][j] ^ state[(i + 2) % 4][j] ^ state[(i + 3) % 4][j];
			/*state[0][0] = state[0][0] * 2 + state[1][0] * 3+ state[2][0] + state[3][0]
			              = multi2[0][0]    + multi3[1][0]   + state[2][0] + state[3][0]
			              = multi2[0][0]    ^ multi3[1][0]   ^ state[2][0] ^ state[3][0] 
			              
			  state[1][0] = state[1][0] * 2 + state[2][0] * 3+ state[3][0] + state[0][0]
			              = multi2[1][0]    ^ multi3[2][0]   ^ state[3][0] ^ state[0][0] 
			              
			  state[2][0] = multi2[2][0]    ^ multi3[3][0]   ^ state[0][0] ^ state[1][0] 
			  							.
										.
										.
			  state[3][3] = multi2[3][3]    ^ multi3[0][3]   ^ state[1][3] ^ state[2][3] 
			  
			  => 先賦值給result是因為如果直接賦值給state，接下來的運算還會用到state的值，
			  這樣值就會是錯的 
			   
			              
			*/ 
		}
		state[0][j] = result[0];
		state[1][j] = result[1];
		state[2][j] = result[2];
		state[3][j] = result[3];	
	}
	
}
int main(){
	FILE *input,*cypher,*pw,*ot;
	
	cypher=fopen("cypher.txt","r");//only for txtmode
	unsigned char itext[16];
	
	srand(time(NULL));
	printf("select AES type: AES-128 / AES-192 / AES-256 => AES-");
	scanf("%d", &AESOption);
	//暫時用這種方式賦值，到時候看要不要直接傳入回合數
	nk = AESOption / 32;
	nr = AESOption / 32 + 6;
		printf("select mode: (1) random key / (2) custom key / (3) debug mode / (4)txt mode => ");
	scanf("%d", &ModeOption);
	
	unsigned char ctext[nk];
	int key[nk];
	
	if (ModeOption == 2){
		printf("AES-%d mode: enter %d words =>", AESOption, AESOption / 8);
		scanf("%s", CipherKey);
	}
	
	if (ModeOption == 3){
		printf("AES-%d mode: enter %d integer(0~255) =>", AESOption, AESOption / 8);
		for (int p = 0; p < AESOption / 8; p++)
			scanf("%d", &CipherKey [p]);	
	}
	if (ModeOption == 4){
		//input CYPHER
		
		for(int i=0;i<AESOption / 8;i++){
		
		if(!feof(cypher)) ctext[i]=getc(cypher);
		else	
			ctext[i]='0';
			
		}
		for(int i=0;i<AESOption / 8;i++){
			CipherKey [i] = ctext[i];
		}
	} 
	
		
	if(ModeOption!=4){
		printf("Plantext:");
		input=fopen("input.txt","w");
		char st[80];
		scanf("%s",&st);
		fprintf(input,"%s",st);
		fclose(input);
	}//input plantext to txt
	
	
	pw = fopen("password.txt","w");//輸出cypherkey 
	for(int c = 0; c < AESOption / 8; c++){
		if (ModeOption == 1)
			CipherKey [c] = (char)(rand() % 256);

		printf("%02X ", CipherKey[c]); // 印出CipherKey 
		block [c] = (unsigned char) CipherKey[c];
		fprintf(pw, "%c", CipherKey[c]);
	}
	printf("\n");
	
	memcpy(ExpandKey, block, sizeof(block));
	
	KeyExpansion();
	//input plantext

	input = fopen("input.txt","r");
	ot = fopen("out.txt","wb");
	while(!feof(input)){
		
		int temp;
		int lessFlag=0;
		for(int i=0;i<16;i++){
			printf("feof(input) [%d]:%d\n",i,feof(input));
			if(!feof(input)){
				itext[i]=getc(input);
			}else{
				lessFlag=1;
				temp=i;
				break;
			}
		}
		if(temp-1==0) break;
		if(lessFlag){
			for(int i=temp-1;i<16;i++){
				itext[i]='0';
			}	
		}
		printf("\nitext:");
		for(int i=0;i<16;i++){
			printf("%c",itext[i]);
		}
		printf("\ntemp:%d\nlessFlag:%d\nfeof(input):%d\n",temp,lessFlag,feof(input));
	
		for(int i=0;i<4;i++){
			for(int j=0;j<4;j++){
				state[j][i] = itext[i*4+j];
			}
		}
		
		int round = 0;
			
	    // round 0 : add round key, 第0回合: 僅執行-key XOR block - key使用[w0 ~ w3]
	    AddRoundKey(round);
	
	    // Round 1 ~ Nr-1, 反覆執行 1 ~ Nr-1回合
	     
	    for (round = 1;round < nr;round++){
	        SubBytes();
	        ShiftRows();
	        MixColumns();
	        AddRoundKey(round);
	    }
		
	    // Round Nr, no MixColumns(), 第 Nr 回合 沒有混合行運算
	    SubBytes();
	    ShiftRows();
	    AddRoundKey(nr);
	
	    /*
	     *  將state[] transform 到 out[]上
	     *  圖示:
	     *   [c0 c4 c8  c12
	     *    c1 c5 c9  c13    --> [c0 c1 c2 ... c15]
	     *    c2 c6 c10 c14
	     *    c3 c7 c11 c15]
	     */
	     
	    for(int i = 0;i < 4;i++) 
	        for(int j = 0;j < 4;j++)
	            out[i * 4 + j]=state[j][i];
		
		printf("out : ");
		for(int i=0;i<16;i++){
			fprintf(ot,"%c",out[i]);
			printf("%c",out[i]);
			//printf("i=%d\n",i);
		}
		printf("\n");
		
	}
	fclose(pw);
	fclose(ot);
	/*
	int round = 0;
		
    // round 0 : add round key, 第0回合: 僅執行-key XOR block - key使用[w0 ~ w3]
    AddRoundKey(round);

    // Round 1 ~ Nr-1, 反覆執行 1 ~ Nr-1回合
     
    for (round = 1;round < nr;round++){
        SubBytes();
        ShiftRows();
        MixColumns();
        AddRoundKey(round);
    }
	
    // Round Nr, no MixColumns(), 第 Nr 回合 沒有混合行運算
    SubBytes();
    ShiftRows();
    AddRoundKey(nr);
    */

    /*
     *  將state[] transform 到 out[]上
     *  圖示:
     *   [c0 c4 c8  c12
     *    c1 c5 c9  c13    --> [c0 c1 c2 ... c15]
     *    c2 c6 c10 c14
     *    c3 c7 c11 c15]
     */
    /*
    for(int i = 0;i < 4;i++) 
        for(int j = 0;j < 4;j++)
            out[i * 4 + j]=state[j][i];
            
    ot = fopen("out.txt","a");
    for(int i=0;i<16;i++){
    	fprintf(ot,"%c",out[i]);
    	
	}
	
	
			
			//printf("%c %d\n",itext[i],reg[i]);
		
	*/	
	
	/*
	fclose(pw);
	fclose(ot);
	for(int i=0;i<16;i++)printf("%d",itext[i]);
	*/
	
	system("pause");
	return 0;
} 
