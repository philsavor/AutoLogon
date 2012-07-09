#include "stdlib.h"
#include "stdio.h"
#include "windows.h"
#include "tchar.h"
#include "time.h"
#include <string>
#include <iostream>
#include "io.h"

char cdDriver[8];

char* trimright(char* str)
{
    char* p = NULL;
    char* s = str;
    for(; *s; s++)
    {
        if(!p)
        {
            if(isspace((int)(*s)))
                p = s;
        }
        else
        {   
            if(!isspace((int)(*s)))
                p = NULL;
        }
    }
    if(p) *p = 0;
    return str;
}

char* TrimQuote(char* value)
{
	char buf[256];
	if(value[0]==0x22 || value[0]==0x27)
		strcpy(buf, value+1);
	int len=strlen(buf);
	if(buf[len-1] == 0x22 || buf[len-1] == 0x27)
		buf[len-1]=0x00;

	strcpy(value, buf);
	return value;
}

char* GetFieldValue(char* filename, char* fieldname, char* value)
{
	char buf[256];
	FILE* fp;
	char* dotp;
	if(NULL==(fp=fopen(filename, "rt")))
	{
		return NULL;
	}

	while(fgets(buf, 256, fp))
	{
		if(strstr(buf, fieldname))
		{
			dotp=strstr(buf, "=");
			strcpy(value, dotp+1);
	//		trimleft(value);
			trimright(value);
			TrimQuote(value);
			return value;
		}
		memset(value, 0x00, sizeof(value));
	}
	fclose(fp);

	return NULL;
}
//修改注册表函数：
// 参数：设置、取消，注销生效，屏蔽Shift键，用户名，密码：返回 1 为失败 0 为成功
int Reg(char User[], char Password[])
{
    HKEY RegKey;

    char AutoUser[] = "DefaultUserName"; // 用户名
    char AutoPass[] = "DefaultPassword"; // 密码
    char Auto[] = "AutoAdminLogon";   // 1 自动登录
    char AutoCount[] = "AutoLogonCount"; // DWORD值，可以设置希望自动登录的次数


    if (ERROR_SUCCESS != RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",0, KEY_ALL_ACCESS, &RegKey))
        return 1;

    char T[]="1";
    DWORD count=1;

    RegSetValueEx(RegKey, AutoUser, 0, REG_SZ, (LPBYTE)User, strlen(User));    // 设置用户名
    RegSetValueEx(RegKey, AutoPass, 0, REG_SZ, (LPBYTE)Password, strlen(Password));  // 设置密码
    RegSetValueEx(RegKey, Auto, 0, REG_SZ, (LPBYTE)T, 1);
    RegSetValueEx(RegKey, AutoCount, 0, REG_DWORD, (const BYTE*)&count, sizeof(DWORD));

    RegCloseKey(RegKey);

    return 0;
}

int ChangeRegeditByContext()
{
	char cLetter;
	char sDrive[8];
	char logbuf[256];
	FILE *fp;
	char config[32];
	char filename[256];
	int cdrom=0;

	for( cLetter = 'D'; cLetter <= 'Z'; cLetter++ )
	{
		sprintf(sDrive, "%c:", cLetter);
		sprintf(config, "%s\\context.sh", sDrive);
		if((fp=fopen(config, "rt")))
		{
			fclose(fp);
			cdrom=1;
			printf("%s%s",config,"\n");
			break;
		}
		
	}
	if( 0 == cdrom)
	{
		printf("NO cdrom!");
		strcpy(config, "C:\\context.sh");
		if((fp=fopen(config, "rt")))
		{
			fclose(fp);
			strcpy(sDrive, "C:");
			printf("%s%s",config,"\n");
		}
		else
		{
			return -1;
		}
	}

	sprintf(filename, "%s\\context.sh", sDrive);

	if(NULL==(fp=fopen(filename, "rt")))
	{
		sprintf(logbuf, "Open file [%s] failed!\n", filename);
		printf(logbuf);
		return -2;
	}

	char password[128];
	if(GetFieldValue(filename, "ADMIN_PASSWD", password))
	{
        Reg("Administrator",password);
		printf("Setting AutoLogon For Once Finished!\n");
	}
	    
   	return 0;
}
/*
void SetInstsrvSrvany()
{
     system("C:\\WINDOWS\\system32\\instsrv.exe NewSid \
		     C:\\WINDOWS\\system32\\srvany.exe");
	 
	//regedit
    HKEY RegKey;

    char AutoUser[] = "DefaultUserName"; // 用户名
    char AutoPass[] = "DefaultPassword"; // 密码
    char Auto[] = "AutoAdminLogon";   // 1 自动登录
    char AutoCount[] = "AutoLogonCount"; // DWORD值，可以设置希望自动登录的次数


    RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\NewSid",0, KEY_ALL_ACCESS, &RegKey)
       

    char T[]="1";
    DWORD count=1;

    RegSetValueEx(RegKey, AutoUser, 0, REG_SZ, (LPBYTE)User, strlen(User));    // 设置用户名
    RegSetValueEx(RegKey, AutoPass, 0, REG_SZ, (LPBYTE)Password, strlen(Password));  // 设置密码
    RegSetValueEx(RegKey, Auto, 0, REG_SZ, (LPBYTE)T, 1);
    RegSetValueEx(RegKey, AutoCount, 0, REG_DWORD, (const BYTE*)&count, sizeof(DWORD));

    RegCloseKey(RegKey);

}*/

int main()
{
	ChangeRegeditByContext();
    //SetInstsrvSrvany();

	return 0;
}