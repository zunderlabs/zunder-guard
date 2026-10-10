import Foundation
import Virtualization
let value:[String:Any]=["api":"Virtualization.framework","supported":VZVirtualMachine.isSupported,"guest_started":false,"restore_downloaded":false]
let bytes=try JSONSerialization.data(withJSONObject:value,options:[.sortedKeys])
print(String(data:bytes,encoding:.utf8)!)
