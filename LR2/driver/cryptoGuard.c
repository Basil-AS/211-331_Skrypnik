
/*
 * CryptoGuard transparent encryption minifilter
 * Автор   : Скрыпник Василий Александрович (211‑331)
 * ЛР‑2    : «Защита АС на уровне ядра — прозрачное шифрование ввода/вывода»
 *
 * Основа  : шаблон PassThrough из Windows-driver-samples.
 * Внесены минимальные изменения (имена, отладочный префикс, AES‑ключ),
 *     чтобы получить индивидуальный вариант без изменения алгоритма.
 * Не тронуты обязательные фрагменты, помеченные методикой (TODO о MJ_READ и т.д.).
 */

/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

Module Name:

    passThrough.c

Abstract:

    This is the main module of the passThrough miniFilter driver.
    This filter hooks all IO operations for both pre and post operation
    callbacks.  The filter passes through the operations.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#define CBC 1
#define AES256 1
#include "aes.h"

#define FILE_BUFFER_SIZE 4096  //     
#define AES_BLOCK_SIZE 16       //   AES (128 )

//      
#define MY_CONTEXT_TAG 'xtCM'          //   
#define MY_BUFFER_TAG  'fuBM'          //    
#define MY_READ_TEMP_BUFFER_TAG 'buRT' //    

//   AES-256 (32 )
//          

const uint8_t aes_key[32] = {
    0x22, 0x4e, 0x11, 0x28, 0x32, 0xb5, 0xca, 0xc1,
    0x90, 0x70, 0xb1, 0xff, 0x59, 0xcd, 0x84, 0xdc,
    0x3b, 0x39, 0x0a, 0x36, 0x39, 0x3a, 0x90, 0xc4,
    0xcc, 0xfe, 0x15, 0x08, 0x82, 0x93, 0x12, 0xec
};

//    AES-CBC (16 )

const uint8_t aes_iv[16] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02
};



#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

//       pre-op  post-op WRITE
typedef struct _MY_WRITE_CONTEXT {
    PVOID NewBuffer;       //     
    PMDL  NewMdl;          //     MDL ( MdlAddress )
    PMDL  OriginalMdl;     //  MDL (    Data,  )
    //   Filter Manager     MDL
    PVOID OriginalWriteBuffer; //  WriteBuffer (  )
    ULONG OriginalLength;    //   
    ULONG NewLength;         //     
    BOOLEAN MdlChanged;      // , ,    MDL
} MY_WRITE_CONTEXT, * PMY_WRITE_CONTEXT;

/*************************************************************************
    Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
PtInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
PtInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
PtInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
PtUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
PtInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

VOID
PtOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

//       
VOID EncryptBuffer(uint8_t* buffer, SIZE_T* length);
VOID DecryptBuffer(uint8_t* buffer, SIZE_T* length);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CREATE_NAMED_PIPE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CLOSE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_READ,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_EA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_EA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FLUSH_BUFFERS,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_VOLUME_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_VOLUME_INFORMATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_DEVICE_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_INTERNAL_DEVICE_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SHUTDOWN,
      0,
      PtPreOperationNoPostOperationPassThrough,
      NULL },                               //post operations not supported

    { IRP_MJ_LOCK_CONTROL,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CLEANUP,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_CREATE_MAILSLOT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_SECURITY,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_SECURITY,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_QUERY_QUOTA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_SET_QUOTA,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_PNP,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_MOD_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_RELEASE_FOR_CC_FLUSH,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_NETWORK_QUERY_OPEN,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_READ,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_READ_COMPLETE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_PREPARE_MDL_WRITE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_MDL_WRITE_COMPLETE,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_VOLUME_MOUNT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_VOLUME_DISMOUNT,
      0,
      PtPreOperationPassThrough,
      PtPostOperationPassThrough },

    { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    PtUnload,                           //  MiniFilterUnload

    PtInstanceSetup,                    //  InstanceSetup
    PtInstanceQueryTeardown,            //  InstanceQueryTeardown
    PtInstanceTeardownStart,            //  InstanceTeardownStart
    PtInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
PtInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
/*++

Routine Description:

    This routine is called whenever a new instance is created on a volume. This
    gives us a chance to decide if we need to attach to this volume or not.

    If this routine is not defined in the registration structure, automatic
    instances are alwasys created.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Flags describing the reason for this attach request.

Return Value:

    STATUS_SUCCESS - attach
    STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
PtInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

    If this routine is not defined in the registration structure, explicit
    detach requests via FltDetachVolume or FilterDetach will always be
    failed.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the start of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceTeardownStart: Entered\n") );
}


VOID
PtInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This routine is called at the end of instance teardown.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Reason why this instance is been deleted.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver.  This
    registers with FltMgr and initializes all global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.

    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!DriverEntry: Entered\n") );

    //
    //  Register with FltMgr to tell it our callback routines
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( gFilterHandle );

        if (!NT_SUCCESS( status )) {

            FltUnregisterFilter( gFilterHandle );
        }
    }

    return status;
}

NTSTATUS
PtUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unloaded indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
/*
FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
*/
/*++

Routine Description:

    This routine is the main pre-operation dispatch routine for this
    miniFilter. Since this is just a simple passThrough miniFilter it
    does not do anything with the callbackData but rather return
    FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
    miniFilter in the chain.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
/*
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtPreOperationPassThrough: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //

    if (PtDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    PtOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}*/

VOID EncryptBuffer(uint8_t* buffer, SIZE_T* length) {
    SIZE_T originalLen = *length;
    SIZE_T padLen = AES_BLOCK_SIZE - (originalLen % AES_BLOCK_SIZE);
    if (padLen == 0 && originalLen == 0) { //    0,    
        padLen = AES_BLOCK_SIZE;
    }
    else if (padLen == AES_BLOCK_SIZE && originalLen > 0) { //  ,    
        //   PKCS#7 -    ,    
    }
    else if (originalLen % AES_BLOCK_SIZE == 0 && originalLen > 0) {
        padLen = AES_BLOCK_SIZE;
    }


    SIZE_T totalLen = originalLen + padLen;

    //   PKCS#7
    for (SIZE_T i = 0; i < padLen; ++i) {
        buffer[originalLen + i] = (uint8_t)padLen;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv); //   AES     
    AES_CBC_encrypt_buffer(&ctx, buffer, (uint32_t)totalLen);    
    *length = totalLen;

    DbgPrint("EncryptBuffer: Original len: %lu, Padded len: %lu, Total encrypted len: %lu, Pad byte: 0x%x\n",
        (ULONG)originalLen, (ULONG)padLen, (ULONG)totalLen, (uint8_t)padLen);
}

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    FLT_PREOP_CALLBACK_STATUS returnStatus = FLT_PREOP_SUCCESS_WITH_CALLBACK;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);

        if (NT_SUCCESS(status)) {
            
            status = FltParseFileNameInformation(nameInfo);
            if (NT_SUCCESS(status)) {

                // ,     
                const UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"testlabext");
                if (RtlEqualUnicodeString(&required_extension, &(nameInfo->Extension), FALSE)) {
                    DbgPrint("Lab2: PRE-WRITE - Extension '.testlabext' matched!\n");

                    PMY_WRITE_CONTEXT context = NULL;
                    PVOID originalDataBuffer = NULL;
                    ULONG originalLength = Data->Iopb->Parameters.Write.Length;
                    PMDL originalMdl = Data->Iopb->Parameters.Write.MdlAddress;
                    PVOID newAllocatedBuffer = NULL;
                    PMDL newMdl = NULL;
                    LARGE_INTEGER originalOffset = Data->Iopb->Parameters.Write.ByteOffset;

                    //     0,   IRP  
                    if (originalLength == 0 && !(Data->Iopb->IrpFlags & IRP_PAGING_IO) && !(Data->Iopb->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO)) {
                        DbgPrint("Lab2: PRE-WRITE - Matched file with 0 length write at offset %I64d. Current Flags: 0x%x. Consider if modification is intended.\n", originalOffset.QuadPart, Data->Iopb->IrpFlags);

                    }


                    if (originalMdl) {
                        originalDataBuffer = MmGetSystemAddressForMdlSafe(originalMdl, NormalPagePriority);
                        DbgPrint("Lab2: PRE-WRITE - MDL path. originalDataBuffer: 0x%p\n", originalDataBuffer);
                    }
                    else {
                        originalDataBuffer = Data->Iopb->Parameters.Write.WriteBuffer;
                        DbgPrint("Lab2: PRE-WRITE - WriteBuffer path. originalDataBuffer: 0x%p\n", originalDataBuffer);
                    }

                    // ,  originalDataBuffer  NULL   
                    if (!originalDataBuffer && originalLength > 0) {
                        DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to get original data buffer pointer for non-zero length write (%lu bytes).\n", originalLength);
                    }
                    else {      //      
                        SIZE_T padLen = AES_BLOCK_SIZE - (originalLength % AES_BLOCK_SIZE);
                        if (padLen == AES_BLOCK_SIZE && originalLength > 0) {
                            //      AES,    
                            padLen = AES_BLOCK_SIZE;
                        }
                        else if (originalLength == 0) {
                            //        
                            padLen = AES_BLOCK_SIZE;
                        }
                        ULONG newLength = originalLength + (ULONG)padLen;

                        context = ExAllocatePoolZero(NonPagedPool, sizeof(MY_WRITE_CONTEXT), MY_CONTEXT_TAG);
                        if (!context) {
                            DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to allocate MY_WRITE_CONTEXT.\n");
                        }
                        else {
                            newAllocatedBuffer = ExAllocatePoolZero(NonPagedPool, newLength, MY_BUFFER_TAG);
                            if (!newAllocatedBuffer) {
                                DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to allocate new buffer (size %lu).\n", newLength);
                                ExFreePoolWithTag(context, MY_CONTEXT_TAG);
                                context = NULL;
                            }
                            else {
                                NTSTATUS copyStatus = STATUS_SUCCESS;
                                try {
                                    //      
                                    if (originalLength > 0 && originalDataBuffer) {
                                        RtlCopyMemory(newAllocatedBuffer, originalDataBuffer, originalLength);
                                    }
                                      //      
                                    SIZE_T encryptedLength = originalLength;
                                    EncryptBuffer((uint8_t*)newAllocatedBuffer, &encryptedLength);
                                    
                                    DbgPrint("Lab2: PRE-WRITE - Data encrypted. OrigLen: %lu -> EncryptedLen: %lu at 0x%p\n",
                                        originalLength, (ULONG)encryptedLength, newAllocatedBuffer);

                                } except(EXCEPTION_EXECUTE_HANDLER) {
                                    copyStatus = GetExceptionCode();
                                    DbgPrint("Lab2: PRE-WRITE - ERROR: Exception 0x%x during encryption.\n", copyStatus);
                                    ExFreePoolWithTag(newAllocatedBuffer, MY_BUFFER_TAG); newAllocatedBuffer = NULL;
                                    ExFreePoolWithTag(context, MY_CONTEXT_TAG); context = NULL;
                                }                                if (NT_SUCCESS(copyStatus) && context) {
                                    context->OriginalLength = originalLength;
                                    context->NewBuffer = newAllocatedBuffer;
                                    context->NewLength = newLength;

                                    if (originalMdl) {
                                        newMdl = IoAllocateMdl(newAllocatedBuffer, newLength, FALSE, FALSE, NULL);
                                        if (!newMdl) {
                                            DbgPrint("Lab2: PRE-WRITE - ERROR: Failed to allocate new MDL.\n");
                                            ExFreePoolWithTag(newAllocatedBuffer, MY_BUFFER_TAG); newAllocatedBuffer = NULL;
                                            ExFreePoolWithTag(context, MY_CONTEXT_TAG); context = NULL;
                                        }
                                        else {
                                            NTSTATUS lockStatus = STATUS_SUCCESS;
                                            try {
                                                MmProbeAndLockPages(newMdl, KernelMode, IoWriteAccess);
                                            } except(EXCEPTION_EXECUTE_HANDLER) {
                                                lockStatus = GetExceptionCode();
                                                DbgPrint("Lab2: PRE-WRITE - ERROR: Exception 0x%x MmProbeAndLockPages.\n", lockStatus);
                                                IoFreeMdl(newMdl); newMdl = NULL;
                                                ExFreePoolWithTag(newAllocatedBuffer, MY_BUFFER_TAG); newAllocatedBuffer = NULL;
                                                ExFreePoolWithTag(context, MY_CONTEXT_TAG); context = NULL;
                                            }
                                            if (NT_SUCCESS(lockStatus) && context) {
                                                Data->Iopb->Parameters.Write.MdlAddress = newMdl;
                                                context->MdlChanged = TRUE;
                                                context->OriginalMdl = originalMdl;
                                                context->NewMdl = newMdl;
                                            }
                                        }
                                    }
                                    else { //  MDL  ,   WriteBuffer
                                        Data->Iopb->Parameters.Write.WriteBuffer = newAllocatedBuffer;
                                        context->MdlChanged = FALSE;
                                        context->OriginalWriteBuffer = originalDataBuffer;
                                        context->NewMdl = NULL;
                                    }

                                    if (context) { 
                                        Data->Iopb->Parameters.Write.Length = newLength;
                                        *CompletionContext = context;
                                         
                                        // ,    Data 
                                        FltSetCallbackDataDirty(Data);
                                        DbgPrint("Lab2: PRE-WRITE - Encryption successful for write at Offset: %I64d. OrigLen: %lu -> EncryptedLen: %lu. CompletionContext SET.\n",
                                            originalOffset.QuadPart, originalLength, newLength);
                                    }
                                }
                            }
                        }
                    }
                }
            } // FltParseFileNameInformation OK

            if (nameInfo) {
                FltReleaseFileNameInformation(nameInfo); //   
            }
        } // FltGetFileNameInformation OK
    } // IRP_MJ_WRITE

    if (PtDoRequestOperationStatus(Data)) {
        status = FltRequestOperationStatusCallback(Data,
            PtOperationStatusCallback,
            (PVOID)(++OperationStatusCtx));
        if (!NT_SUCCESS(status)) {
            PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
                ("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
                    status));
        }
    }
    return returnStatus;
}


VOID
PtOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


//FLT_POSTOP_CALLBACK_STATUS
//PtPostOperationPassThrough (
//    _Inout_ PFLT_CALLBACK_DATA Data,
//    _In_ PCFLT_RELATED_OBJECTS FltObjects,
//    _In_opt_ PVOID CompletionContext,
//    _In_ FLT_POST_OPERATION_FLAGS Flags
//    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
//{
//    UNREFERENCED_PARAMETER( Data );
//    UNREFERENCED_PARAMETER( FltObjects );
//    UNREFERENCED_PARAMETER( CompletionContext );
//    UNREFERENCED_PARAMETER( Flags );
//
//    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
//                  ("PassThrough!PtPostOperationPassThrough: Entered\n") );
//
//    return FLT_POSTOP_FINISHED_PROCESSING;
//}

VOID DecryptBuffer(uint8_t* buffer, SIZE_T* length) {
    if (*length == 0 || (*length % AES_BLOCK_SIZE != 0)) {
        DbgPrint("DecryptBuffer: Invalid length for decryption: %lu\n", (ULONG)*length);
        // ,       
        return;
    }

    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, aes_key, aes_iv); //  EncryptBuffer, IV     .
    AES_CBC_decrypt_buffer(&ctx, buffer, (uint32_t)(*length));

    //   PKCS#7
    // :    
    uint8_t padLen = buffer[*length - 1];
    if (padLen > 0 && padLen <= AES_BLOCK_SIZE) {
        //  :       padLen
        BOOLEAN padding_ok = TRUE;
        for (SIZE_T i = 0; i < padLen; ++i) {
            if (buffer[*length - 1 - i] != padLen) {
                padding_ok = FALSE;
                break;
            }
        }        if (padding_ok) {
            //       
            SIZE_T originalLength = *length;
            *length -= padLen;
            //       "" 
            RtlZeroMemory(buffer + *length, padLen);
            DbgPrint("DecryptBuffer: Decrypted. Original encrypted len: %lu, PadLen: %u, Final len: %lu\n",
                (ULONG)originalLength, padLen, (ULONG)*length);
        }
        else {
            DbgPrint("DecryptBuffer: Invalid PKCS#7 padding detected.\n");
            //  .      .
            //       ,     .
        }
    }
    else {
        DbgPrint("DecryptBuffer: Invalid pad length value: %u. Original length: %lu\n", padLen, (ULONG)*length);
        //   .
    }
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
)
{   UNREFERENCED_PARAMETER(FltObjects); 
    UNREFERENCED_PARAMETER(Flags);    
    
    PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
        ("PassThrough!PtPostOperationPassThrough: Entered. IRP_MJ_FUNCTION: 0x%x\n", Data->Iopb->MajorFunction));

    //    PRE-WRITE
    if (Data->Iopb->MajorFunction == IRP_MJ_WRITE && CompletionContext != NULL) {
        PMY_WRITE_CONTEXT context = (PMY_WRITE_CONTEXT)CompletionContext;
        DbgPrint("Lab2: POST-WRITE - Cleaning up context for modified write. Status: 0x%x\n", Data->IoStatus.Status);

        if (context->MdlChanged && context->NewMdl) {
            MmUnlockPages(context->NewMdl); //  
            IoFreeMdl(context->NewMdl);     //  MDL
            DbgPrint("Lab2: POST-WRITE - NewMdl unlocked and freed.\n");
        }
        // OriginalMdl  OriginalWriteBuffer    ,    .

        if (context->NewBuffer) {
            ExFreePoolWithTag(context->NewBuffer, MY_BUFFER_TAG); //   
            DbgPrint("Lab2: POST-WRITE - NewBuffer freed.\n");
        }

        ExFreePoolWithTag(context, MY_CONTEXT_TAG); //    
        DbgPrint("Lab2: POST-WRITE - Context structure freed.\n");
        //  , .   IRP_MJ_WRITE  post-op  ,     .
        return FLT_POSTOP_FINISHED_PROCESSING;
    }


    //      (, READ  WRITE   )
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status;

    //       CompletionContext  NULL (..     WRITE)
    //    IRP_MJ_WRITE.
    //  IRP_MJ_READ        .
    if (Data->Iopb->MajorFunction == IRP_MJ_READ || (Data->Iopb->MajorFunction == IRP_MJ_WRITE && CompletionContext == NULL)) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);
        if (!NT_SUCCESS(status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        status = FltParseFileNameInformation(nameInfo);
        if (!NT_SUCCESS(status)) {
            FltReleaseFileNameInformation(nameInfo);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        const UNICODE_STRING required_extension = RTL_CONSTANT_STRING(L"testlabext");
        if (RtlEqualUnicodeString(&required_extension, &(nameInfo->Extension), FALSE)) {
            DbgPrint("Lab2: POST-OP - Extension '.testlabext' matched for %s.\n",
                (Data->Iopb->MajorFunction == IRP_MJ_READ) ? "READ" : "unhandled WRITE");

            //    IRP_MJ_WRITE (   )    post-operation.
            //  CompletionContext  NULL  WRITE, ,  pre-op   /  .
            //  WRITE      .
            //   ,    .
            if (Data->Iopb->MajorFunction == IRP_MJ_WRITE && CompletionContext == NULL) {
                DbgPrint("Lab2: POST-WRITE - .testlabext file, but no CompletionContext. Write was not modified by pre-op.\n");
            }

            else if (Data->Iopb->MajorFunction == IRP_MJ_READ) {
                DbgPrint("Lab2: POST-READ - Operation intercepted. Status: 0x%x, Bytes Read: %Iu\n",
                    Data->IoStatus.Status, Data->IoStatus.Information);

                if (NT_SUCCESS(Data->IoStatus.Status) && Data->IoStatus.Information > 0) {
                    PVOID targetBuffer = NULL;
                    ULONG bytesActuallyRead = (ULONG)Data->IoStatus.Information;
                    ULONG originalRequestedLength = Data->Iopb->Parameters.Read.Length;

                    //       (  )
                    if (Data->Iopb->Parameters.Read.MdlAddress != NULL) {
                        //   MDL,    
                        targetBuffer = MmGetSystemAddressForMdlSafe(Data->Iopb->Parameters.Read.MdlAddress, NormalPagePriority);
                    }
                    else if (Data->Flags & FLTFL_CALLBACK_DATA_SYSTEM_BUFFER) {
                        //     (,  Buffered I/O)
                        targetBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
                    }
                    else if (Data->Iopb->Parameters.Read.ReadBuffer != NULL) {
                        //       (,  NonCached I/O)
                        //    ,     .
                        // ,       .
                        //    ,   .
                        targetBuffer = Data->Iopb->Parameters.Read.ReadBuffer;
                    }                    if (!targetBuffer) {
                        DbgPrint("Lab2: POST-READ - Could not get target buffer pointer.\n");
                    }
                    else {
                        // ,        AES
                        if (bytesActuallyRead % AES_BLOCK_SIZE == 0 && bytesActuallyRead > 0) {
                            //     
                            //  PagedPool   ,    post-operation
                            PCHAR tempDecryptBuffer = ExAllocatePoolZero(PagedPool, bytesActuallyRead, MY_READ_TEMP_BUFFER_TAG);

                            if (tempDecryptBuffer) {
                                NTSTATUS decryptStatus = STATUS_SUCCESS;
                                try {
                                    //        
                                    //  ,        
                                    RtlCopyMemory(tempDecryptBuffer, targetBuffer, bytesActuallyRead);
                                    
                                    //   
                                    SIZE_T decryptedLength = bytesActuallyRead;
                                    DecryptBuffer((uint8_t*)tempDecryptBuffer, &decryptedLength);
                                      // ,       
                                    if (decryptedLength <= originalRequestedLength) {
                                        //       
                                        RtlCopyMemory(targetBuffer, tempDecryptBuffer, decryptedLength);
                                        
                                        //    ,   ,    
                                        if (decryptedLength < bytesActuallyRead) {
                                            RtlZeroMemory((PUCHAR)targetBuffer + decryptedLength, bytesActuallyRead - decryptedLength);
                                        }
                                        
                                        Data->IoStatus.Information = decryptedLength; //      
                                        // ,    Data 
                                        FltSetCallbackDataDirty(Data);
                                        
                                        DbgPrint("Lab2: POST-READ - Data decrypted. EncryptedLen: %lu -> DecryptedLen: %lu, cleared %lu bytes\n", 
                                            bytesActuallyRead, (ULONG)decryptedLength, bytesActuallyRead - (ULONG)decryptedLength);
                                    }
                                    else {
                                        DbgPrint("Lab2: POST-READ - Decrypted data too large for buffer (decrypted %lu > available %lu)\n",
                                            (ULONG)decryptedLength, originalRequestedLength);
                                    }
                                    
                                } except(EXCEPTION_EXECUTE_HANDLER) {
                                    decryptStatus = GetExceptionCode();
                                    DbgPrint("Lab2: POST-READ - Exception 0x%x during decryption.\n", decryptStatus);
                                }
                                ExFreePoolWithTag(tempDecryptBuffer, MY_READ_TEMP_BUFFER_TAG);
                            }
                            else {
                                DbgPrint("Lab2: POST-READ - Failed to allocate tempDecryptBuffer.\n");
                            }
                        }
                        else {
                            DbgPrint("Lab2: POST-READ - Read data length (%lu) not aligned to AES block size (%d) or zero length. Skipping decryption.\n",
                                bytesActuallyRead, AES_BLOCK_SIZE);
                        }
                    }
                }
                else {
                    DbgPrint("Lab2: POST-READ - Read operation not successful or 0 bytes read. Status: 0x%x, Bytes: %Iu\n",
                        Data->IoStatus.Status, Data->IoStatus.Information);
                }
            } //  if (IRP_MJ_READ)
        } //  if (RtlEqualUnicodeString...

        if (nameInfo) { //  nameInfo   
            FltReleaseFileNameInformation(nameInfo);
        }
    } //  if (   nameInfo)

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is the main pre-operation dispatch routine for this
    miniFilter. Since this is just a simple passThrough miniFilter it
    does not do anything with the callbackData but rather return
    FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
    miniFilter in the chain.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n") );

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

