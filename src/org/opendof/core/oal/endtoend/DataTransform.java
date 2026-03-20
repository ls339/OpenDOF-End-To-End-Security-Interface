package org.opendof.core.oal.endtoend;

import org.opendof.core.oal.DOFInterfaceID;

public interface DataTransform {
    byte[] transformSendData(DOFInterfaceID interfaceID, byte[] data);
    byte[] transformReceiveData(DOFInterfaceID interfaceID, byte[] data);
}
