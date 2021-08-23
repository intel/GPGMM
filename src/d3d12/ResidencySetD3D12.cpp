#include "src/d3d12/ResidencySetD3D12.h"

#include "src/common/Assert.h"

namespace gpgmm { namespace d3d12 {
    void ResidencySet::Insert(Heap* heap) {
        ASSERT(heap != nullptr);
        bool inserted = mSet.insert(heap).second;
        if (inserted) {
            mToMakeResident.push_back(heap);
        }
    }

    void ResidencySet::Reset() {
        mSet.clear();
        mToMakeResident.clear();
    }
}}  // namespace gpgmm::d3d12