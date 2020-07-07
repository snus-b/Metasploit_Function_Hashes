#!/usr/bin/env python
import os
import sys
import argparse
try:
    import pefile
except:
    print "Error could not locate pefile. \nInstall pefile\n\t pip install pefile"
    sys.exit(1)    

ror = lambda val, r_bits, max_bits: \
    ((val&(2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

def iterate_dll_exports( dllName ):                                                
    dll = pefile.PE( dllName )                                                     
    ret = []                                                                       
    shortName = os.path.split(dllName)[-1]
    for exp in dll.DIRECTORY_ENTRY_EXPORT.symbols:                                 
        if exp.name == None: continue                                              
        ret.append( {'address':dll.OPTIONAL_HEADER.ImageBase+exp.address,          
                     'funcName': exp.name,                                         
                     'ordinal': exp.ordinal,                                       
                     'hash': gen_function_hash( [shortName, exp.name.strip() ] ) } )                 
    return { 'dllName':dllName, 'dllHash': gen_file_hash(shortName), 'funcHashs':ret }
                                                                                   
def print_dll_exports( hashList ):                                                 
    ret = '[+] %s: 0x%08X\n' % ( hashList['dllName'], hashList['dllHash'] )        
    ret += '\t[ordinal ] Hash: Function Name (Address)\n'                          
    for func in hashList['funcHashs']:                                             
        try:
            ret += '\t[%08d] msf_hash(0x%08X): %s (0x%08X)\n' % (                                
                    func['ordinal'],                                                   
                    func['hash'],
                    func['funcName'],                                                  
                    func['address'],                                                   
                    )                                                     
        except:
            ret += '\t[%08d] msf_hash(%r): %s (0x%08X)\n' % (                                
                    func['ordinal'],                                                   
                    func['hash'],
                    func['funcName'],                                                  
                    func['address'],                                                   
                    )                                                     
    print ret           

def gen_file_hash( name ):
    name = uni(name.upper())
    l_hash = 0
    for c in name+'\x00\x00':
        l_hash = ror( l_hash, 0xd, 32 )
        l_hash = (l_hash + ord(c) ) & 0xffffffff
    return l_hash

def gen_function_hash( data ):
    l_hash = 0
    name = data[1]
    for c in name+'\x00':
        l_hash = ror( l_hash, 0xd, 32 )
        l_hash = (l_hash + ord(c) ) & 0xffffffff
    l_hash = (l_hash + gen_file_hash( data[0]) ) & 0xffffffff
#    print '%15s: 0x%08x' % ( name, l_hash )
    return l_hash
def uni( name ):
    ret = ''
    for i in name:
        ret += i+'\x00'
    return ret


def explicit( ):
    l = [ ['kernel32.dll','LoadLibraryA'], 
#      ['kernel32.dll','WaitForSingleObject'], 
#      ['ws2_32.dll','WSAStartup'], 
#      ['ws2_32.dll','WSASocketA'], 
#      ['ws2_32.dll','bind'], 
#      ['ws2_32.dll','listen'], 
#      ['ws2_32.dll','accept'], 
#      ['ws2_32.dll','closesocket'], 
#      ["kernel32.dll","LoadLibraryA"],
#      ["kernel32.dll","GetVersion"],
#      ["kernel32.dll","GetLastError"],
#      ["kernel32.dll","SetUnhandledExceptionFilter"],
#      ["kernel32.dll","CreateFileA"],
#      ["kernel32.dll","DeleteFileA"],
#      ["kernel32.dll","ReadFile"],
#      ["kernel32.dll","ReadFileEx"],
#      ["kernel32.dll","WriteFile"],
#      ["kernel32.dll","WriteFileEx"],
#      ["kernel32.dll","SetEvent"],
#      ["kernel32.dll","GetTempPathA"],
#      ["kernel32.dll","CloseHandle"],
      ["kernel32.dll","VirtualAlloc"],
#      ["kernel32.dll","VirtualAllocEx"],
#      ["kernel32.dll","VirtualFree"],
#      ["kernel32.dll","CreateProcessA"],
#      ["kernel32.dll","WriteProcessMemory"],
#      ["kernel32.dll","CreateRemoteThread"],
#      ["kernel32.dll","GetProcAddress"],
#      ["kernel32.dll","WaitForSingleObject"],
#      ["kernel32.dll","Sleep"],
#      ["kernel32.dll","WinExec"],
#      ["kernel32.dll","ExitProcess"],
#      ["kernel32.dll","CreateThread"],
#      ["kernel32.dll","ExitThread"],
#      ["kernel32.dll","CreateNamedPipeA"],
#      ["kernel32.dll","CreateNamedPipeW"],
#      ["kernel32.dll","ConnectNamedPipe"],
#      ["kernel32.dll","DisconnectNamedPipe"],
#      ["kernel32.dll","lstrlenA"],
#      ["ntdll.dll","RtlCreateUserThread"],
#      ["ntdll.dll","RtlExitUserThread"],
#      ["advapi32.dll","RevertToSelf"],
#      ["advapi32.dll","StartServiceCtrlDispatcherA"],
#      ["advapi32.dll","RegisterServiceCtrlHandlerExA"],
#      ["advapi32.dll","SetServiceStatus"],
#      ["advapi32.dll","OpenSCManagerA"],
#      ["advapi32.dll","OpenServiceA"],
#      ["advapi32.dll","ChangeServiceConfig2A"],
#      ["advapi32.dll","CloseServiceHandle"],
#      ["user32.dll","GetDesktopWindow"],
#      ["ws2_32.dll","WSAStartup"],
#      ["ws2_32.dll","WSASocketA"],
#      ["ws2_32.dll","WSAAccept"],
#      ["ws2_32.dll","bind"],
#      ["ws2_32.dll","listen"],
#      ["ws2_32.dll","accept"],
#      ["ws2_32.dll","closesocket"],
#      ["ws2_32.dll","connect"],
#      ["ws2_32.dll","recv"],
#      ["ws2_32.dll","send"],
#      ["ws2_32.dll","setsockopt"],
#      ["ws2_32.dll","gethostbyname"],
#      ["wininet.dll","InternetOpenA"],
#      ["wininet.dll","InternetConnectA"],
#      ["wininet.dll","HttpOpenRequestA"],
#      ["wininet.dll","HttpSendRequestA"],
#      ["wininet.dll","InternetErrorDlg"],
#      ["wininet.dll","InternetReadFile"],
#      ["wininet.dll","InternetSetOptionA"],
#      ["winhttp.dll","WinHttpOpen"],
#      ["winhttp.dll","WinHttpConnect"],
#      ["winhttp.dll","WinHttpOpenRequest"],
#      ["winhttp.dll","WinHttpSendRequest"],
#      ["winhttp.dll","WinHttpReceiveResponse"],
#      ["winhttp.dll","WinHttpReadData"],
#      ["dnsapi.dll","DnsQuery_A"],
#      ["pstorec.dll","PStoreCreateInstance"],
#      ['',''], 
      ]
    for i in l:
        print 'TEST: 0x%08X' % gen_file_hash( i[0] )
        print '%15s: 0x%08x' % ( i, gen_function_hash( i )  )
        print '-'*20

def main():
    parser = argparse.ArgumentParser( description="Used to compute the hash of the functions exported from the DLL")
    parser.add_argument( '-d', action='store', dest='directory', help="Directory to search for DLL's" )
    parser.add_argument( '-i', action='store', dest='dll_filename', help="The path location of an individual DLL to hash the exported functions" )
    parser.add_argument( '-o', action='store', dest='old_method', help="Hardcoded DLL/Function pair method" )
    results = parser.parse_args()

    if results.directory==None and \
            results.dll_filename==None and \
            results.old_method==None:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if results.directory:
        print "Beginning Directory search"  
        for f in os.listdir( results.directory ):                               
            if not f[-4:] == '.dll': continue                                   
            x = iterate_dll_exports( os.path.join( results.directory, f) )                                        
            print_dll_exports( x )   
    if results.dll_filename:                                                    
        print "Beginning individual DLL"                                          
        try:                                                                    
            import pefile                                                       
        except:                                                                 
            print "Error could not locate pefile. \nInstall pefile\n\t pip install pefile"
            sys.exit(1)                                                         
        x = iterate_dll_exports( results.dll_filename )                         
        print_dll_exports( x )                                                  
    if results.old_method:                                                      
        explicit()  

if __name__=='__main__':
    main()
