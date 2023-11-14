#pragma once

#include "resource.h"
#include <Windows.h>
#include <tchar.h>
#include <bitset>
#include <winioctl.h>
#include <iostream>
#include <vector>
#include <string>
using namespace std;


#define BufferLength 1024

struct MBR_disk_entry
{
	uint8_t bootflag;//引导标志
	uint8_t citouhao;//磁头号
	uint8_t shanquhao;//扇区号
	uint8_t zhumianhao;//柱面号
	uint8_t disk_flag;//分区类型标志
	uint8_t someinfo[3];//id、结束磁头号、结束柱面号、结束扇区号
	uint8_t relative[4];//相对起始扇区
	uint8_t sectors[4];//总扇区数
};
struct MBR
{
	uint8_t boot_code[446];//引导代码
	//4个分区表，每个16字节,只有一个分区表有内容，对应的标志是0xEE
	MBR_disk_entry pation_table_entry[4];
	uint8_t endflag[2];//55AA
};

struct BPB
{
	uint8_t BytePerSec[2];//每扇区字节数
	uint8_t SecPerClus;//每簇扇区数
	uint8_t RsvdSecCnt[2];//DOS保留扇区数
	uint8_t NumFATs;//FAT表个数
	uint8_t RootEntCnt[2];//未用
	uint8_t TotSec16[2];//未用
	uint8_t Media;//介质描述符
	uint8_t FATSz16[2];//未用
	uint8_t SecPerTrk[2];//每磁道扇区数
	uint8_t NumHeads[2];//磁头数
	uint8_t HidSec[4];//隐藏扇区
	uint8_t TotSec32[4];//该分区的扇区总数
	uint8_t FATSz32[4];//每FAT扇区数
	uint8_t	ExtFlags[2];//标记
	uint8_t FSVers[2];//版本
	uint8_t RootClus[4];//根目录首簇号
	uint8_t FSInfo[2];//文件系统信息扇区号
	uint8_t BkBootSec[2];//DBR备份扇区号
	uint8_t Reserved[12];//保留
	uint8_t DrvNum;//BIOS驱动器号
	uint8_t Reserved1;//未用
	uint8_t BootSig;//扩展引导标记
	uint8_t VolID[4];//卷序列号
	uint8_t VolLab[11];//卷标
	uint8_t FilSysType[8];//文件系统类型
};

struct DBR
{
	uint8_t BootSec_jmpBoot[3];
	uint8_t BootSec_OEMName[8];
	BPB bpb;
	uint8_t bootcode[420];
	uint8_t signature[2];//55 AA
};

struct
{
	vector<string> vec;//存放待输出数据
	vector<uint32_t> vec2;//存放分区表起始扇区
}v;


//将四个连续字节存放的值转为int型
uint32_t transtoint(unsigned char a[])
{
	uint32_t sum = 0;
	for (int i = 0; i < 4; i++) {
		int m = a[i] / 16;
		int n = a[i] % 16;
		float len = 16;
		int temp1 = m * (pow(len, 7 - 2 * i));
		int temp2 = n * (pow(len, 6 - 2 * i));
		sum = sum + temp1 + temp2;
	}
	return sum;
}

//十进制转十六进制
string unsignedCharToHexString(unsigned char ch) {
	const char hex_chars[] = "0123456789abcdef";
	string result = "";
	unsigned int highHalfByte = (ch >> 4) & 0x0f;
	unsigned int lowHalfByte = (ch & 0x0f);
	result += hex_chars[highHalfByte];
	result += hex_chars[lowHalfByte];
	return result;
}

//找到分区表起始扇区
bool find_patition(MBR* mbr, char* lpBuffer, size_t len, bool ismbr, ULONGLONG* baseaddr, ULONGLONG* nextaddr, int EBRnum)
{
	bool mbrflag = 1;//在读取MBR的时候判断条目是主分区还是扩展分区条目 
	for (int i = 0; i < 446; i++) {
		mbr->boot_code[i] = lpBuffer[i];
	}
	int cnt = 446;
	for (int i = 0; i < 4; i++) {
		mbr->pation_table_entry[i].bootflag = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].citouhao = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].shanquhao = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].zhumianhao = lpBuffer[cnt];
		cnt++;
		mbr->pation_table_entry[i].disk_flag = lpBuffer[cnt];
		cnt++;
		for (int j = 0; j < 3; j++) {
			mbr->pation_table_entry[i].someinfo[j] = lpBuffer[cnt];
			cnt++;
		}
		for (int j = 0; j < 4; j++) {
			mbr->pation_table_entry[i].relative[j] = lpBuffer[cnt];
			cnt++;
		}
		for (int j = 0; j < 4; j++) {
			mbr->pation_table_entry[i].sectors[j] = lpBuffer[cnt];
			cnt++;
		}
	}
	for (int i = 0; i < 2; i++) {
		mbr->endflag[i] = lpBuffer[cnt];
		cnt++;
	}

	string mystr;
	if (ismbr) {
		for (int i = 0, rank = 1; i < 4; i++, rank++) {
			if (mbr->pation_table_entry[i].disk_flag == 0x5 || mbr->pation_table_entry[i].disk_flag == 0xf) {
				mbrflag = 0;
				rank = 4;
			}
			if (mbr->pation_table_entry[i].disk_flag == 0x00)//当第五位（标志位）是00时，代表分区表信息为空，无分区
			{
				//也不用往后读了 
				mystr = "";
			}
			else {
				uint8_t center[4];
				for (int j = 0, k = 3; j < 4; j++, k--) {
					center[j] = mbr->pation_table_entry[i].relative[k];
				}
				uint32_t tempadd = transtoint(center);
				v.vec2.push_back(tempadd);

				if (ismbr && !mbrflag)// if in mbr and got a extend entry,the EBR at relsecor+nowbase(0)
				{
					*baseaddr = (ULONGLONG)tempadd + (*baseaddr);//only change once
					*nextaddr = (ULONGLONG)0UL;
					//*nextaddr = (ULONGLONG)tempadd;
				}
			}
		}
	}
	else {
		int cnt = 0;
		for (;cnt < 2;) {
			if (mbr->pation_table_entry[cnt].disk_flag == 0x5) {
				mbrflag = 0;
			}
			if (mbr->pation_table_entry[cnt].disk_flag == 0x0) {
				mbrflag = 1;
			}
			else {
				uint8_t center[4];
				if (cnt == 0) {
					for (int j = 0, k = 3; j < 4; j++, k--) {
						center[j] = mbr->pation_table_entry[cnt].relative[k];
					}
					uint32_t tempadd = transtoint(center);
					v.vec2.push_back((ULONGLONG)tempadd + (*nextaddr) + (*baseaddr));
				}
				else {
					for (int j = 0, k = 3; j < 4; j++, k--) {
						center[j] = mbr->pation_table_entry[cnt].relative[k];
					}
					uint32_t tempadd = transtoint(center);
					*nextaddr = (ULONGLONG)tempadd;
				}
			}
			cnt++;
		}
	}
	return (mbrflag);
}

//FAT32文件系统解析
bool FATMsg(DBR* dbr, char* lpBuffer, size_t len, int num, uint32_t clus, HANDLE hDevice) {
	string mystr;
	mystr = "第" + to_string(num);
	mystr += "磁盘FAT解析: ";
	v.vec.push_back(mystr);

	//把读取的值传入DBR
	int cnt = 0;
	for (int i = 0; i < 3; i++) {
		dbr->BootSec_jmpBoot[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 8; i++) {
		dbr->BootSec_OEMName[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.BytePerSec[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.SecPerClus = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 2; i++) {
		dbr->bpb.RsvdSecCnt[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.NumFATs = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 2; i++) {
		dbr->bpb.RootEntCnt[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.TotSec16[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.Media = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 2; i++) {
		dbr->bpb.FATSz16[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.SecPerTrk[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.NumHeads[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.HidSec[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.TotSec32[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.FATSz32[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.ExtFlags[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.FSVers[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 4; i++) {
		dbr->bpb.RootClus[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.FSInfo[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 2; i++) {
		dbr->bpb.BkBootSec[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 12; i++) {
		dbr->bpb.Reserved[i] = lpBuffer[cnt];
		cnt++;
	}
	dbr->bpb.DrvNum = lpBuffer[cnt];
	cnt++;
	dbr->bpb.Reserved1 = lpBuffer[cnt];
	cnt++;
	dbr->bpb.BootSig = lpBuffer[cnt];
	cnt++;
	for (int i = 0; i < 4; i++) {
		dbr->bpb.VolID[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 11; i++) {
		dbr->bpb.VolLab[i] = lpBuffer[cnt];
		cnt++;
	}
	for (int i = 0; i < 8; i++) {
		dbr->bpb.FilSysType[i] = lpBuffer[cnt];
		cnt++;
	}

	//解析BPB，找到FAT和根目录位置
	mystr = "";
	v.vec.push_back("每扇区字节数:");
	uint8_t temp[4] = {0};
	for (int j = 0, k = 1; j < 2; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.BytePerSec[k]);
		mystr += " ";
		temp[j+2] = dbr->bpb.BytePerSec[k];
	}
	mystr += "h = ";
	uint32_t tempadd = transtoint(temp);
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("每簇扇区数:");
	mystr += to_string(dbr->bpb.SecPerClus);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("保留扇区数:");
	for (int j = 0, k = 1; j < 2; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.RsvdSecCnt[k]);
		mystr += " ";
		temp[j+2] = dbr->bpb.RsvdSecCnt[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	uint32_t rsv = tempadd;
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("FAT表数目:");
	mystr += to_string(dbr->bpb.NumFATs);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("扇区总数:");
	for (int j = 0, k = 3; j < 4; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.TotSec32[k]);
		mystr += " ";
		temp[j] = dbr->bpb.TotSec32[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("每FAT扇区数:");
	for (int j = 0, k = 3; j < 4; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.FATSz32[k]);
		mystr += " ";
		temp[j] = dbr->bpb.FATSz32[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	uint32_t spf = tempadd;
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("根目录首簇号:");
	for (int j = 0, k = 3; j < 4; j++, k--) {
		mystr += unsignedCharToHexString(dbr->bpb.RootClus[k]);
		mystr += " ";
		temp[j] = dbr->bpb.RootClus[k];
	}
	mystr += "h = ";
	tempadd = transtoint(temp);
	mystr += to_string(tempadd);
	v.vec.push_back(mystr);

	mystr = "";
	v.vec.push_back("FAT1的扇区号=DBR所在扇区+保留扇区:");
	uint32_t temp2 = clus + rsv;
	v.vec.push_back(to_string(temp2));

	mystr = "";
	v.vec.push_back("根目录的扇区号=FAT1的扇区号+2*(每一个FAT表扇区数):");
	uint32_t temp3 = temp2 + (2 * spf);
	v.vec.push_back(to_string(temp2));

	/*查找文件：
	跳到根目录扇区，对于每一个文件，单独处理
	1.每次读取32字节，长短文件判断，若为长文件，则判断长文件名长度，一直到下一个0B位是短文件名标志
	2.对于不同文件，读取簇号
	3.跳到FAT表，读取簇链
	4.根据簇链跳到相应簇得到数据
	*/
	v.vec.push_back("//////////////////");
	char myBuf[BufferLength] = { 0 };
	LARGE_INTEGER offset2;
	DWORD dwCB2;
	offset2.QuadPart = ((ULONGLONG)temp3) * ((ULONGLONG)512);
	SetFilePointer(hDevice, offset2.LowPart, &offset2.HighPart, FILE_BEGIN);
	ReadFile(hDevice, myBuf, 512, &dwCB2, NULL);
	bool fin = false;

	for (int q = 0; fin == false;) {
		if ((uint8_t)myBuf[q + 11] == 0x0) {//已经没有文件了，结束
			fin = true;
			break;
		}
		else {
			if ((uint8_t)myBuf[q + 11] == 0x8) {//卷标
				q = q + 32;
				continue;
			}
			if ((uint8_t)myBuf[q + 11] == 0xf) {//长文件
				uint8_t c = myBuf[q];
				if (c == 0xe5) {//删除了的文件
					q = q + 32;
					continue;
				}
				q = q + ((int)((uint8_t)myBuf[q] - (0x40)) * 32);
				continue;
			}
			else {//短文件
				if ((uint8_t)myBuf[q] == 0xe5) {//删除了的文件
					q = q + 32;
					continue;
				}
				else {
					string mystr2 = "";
					v.vec.push_back("文件起始簇号:");
					temp[0] = myBuf[q + 21];
					temp[1] = myBuf[q + 20];
					temp[2] = myBuf[q + 27];
					temp[3] = myBuf[q + 26];
					mystr2 += unsignedCharToHexString(myBuf[q + 21]);
					mystr2 += unsignedCharToHexString(myBuf[q + 20]);
					mystr2 += unsignedCharToHexString(myBuf[q + 27]);
					mystr2 += unsignedCharToHexString(myBuf[q + 26]);
					uint32_t b_clus = transtoint(temp);
					v.vec.push_back(to_string(b_clus));

					//跳到FAT表并读取簇号链
					char myBuf2[BufferLength] = { 0 };
					offset2.QuadPart = ((ULONGLONG)temp2) * ((ULONGLONG)512);
					SetFilePointer(hDevice, offset2.LowPart, &offset2.HighPart, FILE_BEGIN);
					ReadFile(hDevice, myBuf2, 512, &dwCB2, NULL);

					v.vec.push_back("文件簇号链:");
					mystr = to_string(b_clus);
					mystr += "->";
					tempadd = b_clus;
					
					for (int w = (int)b_clus; mystr2 != "0fffffff";) {
						mystr2 = "";
						temp[0] = myBuf2[w * 4 + 3];
						temp[1] = myBuf2[w * 4 + 2];
						temp[2] = myBuf2[w * 4 + 1];
						temp[3] = myBuf2[w * 4];
						tempadd = transtoint(temp);
						mystr += unsignedCharToHexString(myBuf2[w * 4 + 3]);
						mystr += unsignedCharToHexString(myBuf2[w * 4 + 2]);
						mystr += unsignedCharToHexString(myBuf2[w * 4 + 1]);
						mystr += unsignedCharToHexString(myBuf2[w * 4]);
						mystr2 += unsignedCharToHexString(myBuf2[w * 4 + 3]);
						mystr2 += unsignedCharToHexString(myBuf2[w * 4 + 2]);
						mystr2 += unsignedCharToHexString(myBuf2[w * 4 + 1]);
						mystr2 += unsignedCharToHexString(myBuf2[w * 4]);
						mystr += "->";
						if (mystr.size() > 60) {
							v.vec.push_back(mystr);
							mystr = "";
						}
						if (mystr2 == "0fffffff" || mystr2 == "00000000") {//结束标志，若文件太大，其在一个扇区最后一个簇存放的是“00000000”
							break;
						}
						w = w + (tempadd - w);
					}
					v.vec.push_back(mystr);

					v.vec.push_back("文件数据起始扇区=根目录起始扇区号+(起始簇号-2)x每簇的扇区数:");
					uint32_t temp4 = temp3 + ((uint32_t)dbr->bpb.SecPerClus * (b_clus - 2));
					v.vec.push_back(to_string(temp4));
					v.vec.push_back("////////////////////////////////");
					q = q + 32;
				}
			}
		}
	}
	return fin;
}

bool GetDriveMsg(DISK_GEOMETRY* pdg, int addr)
{
	HANDLE hDevice;               // 设备句柄
	BOOL bResult;                 // results flag
	DWORD junk;                   // discard resultscc
	char lpBuffer[BufferLength] = { 0 };
	MBR* mbr = new MBR;
	DBR* dbr = new DBR;


	//通过CreateFile来获得设备的句柄
	hDevice = CreateFile(TEXT("\\\\.\\PhysicalDrive1"), // 设备名称
		GENERIC_READ,                // no access to the drive
		FILE_SHARE_READ | FILE_SHARE_WRITE,  // share mode
		NULL,             // default security attributes
		OPEN_EXISTING,    // disposition
		0,                // file attributes
		NULL);            // do not copy file attributes
	if (hDevice == INVALID_HANDLE_VALUE) // cannot open the drive
	{
		return (FALSE);
	}

	//通过DeviceIoControl函数与设备进行IO
	bResult = DeviceIoControl(hDevice, // 设备的句柄
		IOCTL_DISK_GET_DRIVE_GEOMETRY, // 控制码，指明设备的类型
		NULL,
		0, // no input buffer
		pdg,
		sizeof(*pdg),
		&junk,                 // # bytes returned
		(LPOVERLAPPED)NULL); // synchronous I/O

	LARGE_INTEGER offset;//long long signed
	offset.QuadPart = (ULONGLONG)addr * (ULONGLONG)512;//a sector
	SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//从0开始读MBR
	if (GetLastError())
		return (FALSE);//如果出错了

	DWORD dwCB;
	//从这个位置开始读 
	BOOL bRet = ReadFile(hDevice, lpBuffer, 512, &dwCB, NULL);
	
	bool finished = 0;
	int EBRnum = 0;
	ULONGLONG* baseaddr = new ULONGLONG, * nextaddr = new ULONGLONG;//扩展分区起始地址，EBR地址 
	*baseaddr = (ULONGLONG)0;
	*nextaddr = (ULONGLONG)0;
	finished = find_patition(mbr, lpBuffer, 512, true, baseaddr, nextaddr, EBRnum);

	if (finished)
		CloseHandle(hDevice);
	else
	{
		//继续读
		do {
			EBRnum++;
			memset(lpBuffer, 0, sizeof(lpBuffer));
			offset.QuadPart = (ULONGLONG)((*baseaddr)*((ULONGLONG)512) + (*nextaddr)*((ULONGLONG)512));//find the EBR
			SetFilePointer(hDevice, offset.LowPart, &offset.HighPart, FILE_BEGIN);//读EBR
			ReadFile(hDevice, lpBuffer, 512, &dwCB, NULL);
		} while (!find_patition(mbr, lpBuffer, 512, false, baseaddr, nextaddr, EBRnum));
		//CloseHandle(hDevice);
	}

	//FAT message
	LARGE_INTEGER offset3;
	offset3.QuadPart = (ULONGLONG)addr * (ULONGLONG)512;
	SetFilePointer(hDevice, offset3.LowPart, &offset3.HighPart, FILE_BEGIN);
	int order = 1;
	for (int i = 0; i < v.vec2.size(); i++) {
		if (i == 3) {
			continue;
		}

		memset(lpBuffer, 0, sizeof(lpBuffer));
		offset3.QuadPart = (ULONGLONG)((ULONGLONG)(v.vec2[i]) * ((ULONGLONG)512));//find the address
		SetFilePointer(hDevice, offset3.LowPart, &offset3.HighPart, FILE_BEGIN);//读DBR
		ReadFile(hDevice, lpBuffer, 512, &dwCB, NULL);
		FATMsg(dbr, lpBuffer, 512, order, v.vec2[i], hDevice);
		order++;
	}
	CloseHandle(hDevice);
	delete mbr;
	delete dbr;
	delete baseaddr;
	delete nextaddr;
	return bResult;
}
