def predict(sample):
    if sample['MinorImageVersion'] <= 2.500000:
        if sample['SectionAlignment'] <= 6.500000:
            if sample['e_cparhdr'] <= 0.500000:
                if sample['SizeOfStackCommit'] <= 0.500000:
                    return 0  # 0: Benign, 1: Malware
                else:
                    if sample['SectionMaxVirtual'] <= 516.000000:
                        return 1  # 0: Benign, 1: Malware
                    else:
                        return 0  # 0: Benign, 1: Malware
            else:
                if sample['SectionMinVirtualsize'] <= 733.500000:
                    if sample['MajorLinkerVersion'] <= 13.500000:
                        if sample['ImageDirectoryEntryExport'] <= 283.000000:
                            if sample['MajorImageVersion'] <= 9.500000:
                                if sample['MajorLinkerVersion'] <= 11.500000:
                                    if sample['e_cp'] <= 2.500000:
                                        if sample['SizeOfInitializedData'] <= 149.500000:
                                            if sample['ImageDirectoryEntryResource'] <= 34.000000:
                                                if sample['SizeOfImage'] <= 72.500000:
                                                    if sample['DllCharacteristics'] <= 30.000000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['SizeOfCode'] <= 109.000000:
                                                            if sample['ImageDirectoryEntrySecurity'] <= 2889.500000:
                                                                if sample['SectionMaxVirtual'] <= 46.500000:
                                                                    if sample['e_oeminfo'] <= 2.000000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SuspiciousImportFunctions'] <= 11.000000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['SizeOfInitializedData'] <= 63.000000:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                        else:
                                                                            if sample['SectionMaxPointerData'] <= 108.500000:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                            else:
                                                                                if sample['SectionMaxPhysical'] <= 2262.000000:
                                                                                    return 1  # 0: Benign, 1: Malware
                                                                                else:
                                                                                    if sample['ImageDirectoryEntrySecurity'] <= 1584.500000:
                                                                                        return 1  # 0: Benign, 1: Malware
                                                                                    else:
                                                                                        if sample['ImageDirectoryEntrySecurity'] <= 1653.500000:
                                                                                            return 0  # 0: Benign, 1: Malware
                                                                                        else:
                                                                                            return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['DirectoryEntryImportSize'] <= 48.000000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SizeOfInitializedData'] <= 54.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['ImageDirectoryEntrySecurity'] <= 413.000000:
                                                                        if sample['SizeOfInitializedData'] <= 63.500000:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['DirectoryEntryImportSize'] <= 97.000000:
                                                        if sample['ImageDirectoryEntrySecurity'] <= 3110.000000:
                                                            if sample['SectionMaxPhysical'] <= 2332.000000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SectionMaxPhysical'] <= 2359.500000:
                                                                    if sample['SizeOfImage'] <= 80.500000:
                                                                        if sample['SizeOfInitializedData'] <= 84.500000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            if sample['ImageDirectoryEntrySecurity'] <= 1020.500000:
                                                                                return 0  # 0: Benign, 1: Malware
                                                                            else:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SectionMaxVirtual'] <= 67.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['SizeOfImage'] <= 105.500000:
                                                        if sample['CheckSum'] <= 3715.500000:
                                                            return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                        else:
                                            if sample['ImageDirectoryEntryImport'] <= 3891.500000:
                                                if sample['NumberOfSections'] <= 6.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['CheckSum'] <= 11363.500000:
                                                        if sample['MajorImageVersion'] <= 3.000000:
                                                            if sample['MajorOperatingSystemVersion'] <= 2.000000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['ImageDirectoryEntryImport'] <= 3778.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['SectionMaxPointerData'] <= 146.500000:
                                                                if sample['DllCharacteristics'] <= 47.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SizeOfInitializedData'] <= 425.000000:
                                                                    if sample['SizeOfImage'] <= 115.500000:
                                                                        if sample['CheckSum'] <= 3732.000000:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                        else:
                                                                            if sample['TimeDateStamp'] <= 10057.500000:
                                                                                if sample['CheckSum'] <= 10463.000000:
                                                                                    if sample['CheckSum'] <= 8944.000000:
                                                                                        return 1  # 0: Benign, 1: Malware
                                                                                    else:
                                                                                        return 0  # 0: Benign, 1: Malware
                                                                                else:
                                                                                    return 1  # 0: Benign, 1: Malware
                                                                            else:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SectionMaxPhysical'] <= 6096.500000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['TimeDateStamp'] <= 9890.500000:
                                                            if sample['AddressOfEntryPoint'] <= 4595.000000:
                                                                return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SizeOfImage'] <= 148.000000:
                                                                    if sample['CheckSum'] <= 11443.500000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['CheckSum'] <= 11520.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SectionMaxPhysical'] <= 6958.000000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['AddressOfEntryPoint'] <= 8774.000000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['MajorImageVersion'] <= 5.500000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                    else:
                                        if sample['MinorOperatingSystemVersion'] <= 1.500000:
                                            if sample['SectionMaxPhysical'] <= 9806.000000:
                                                if sample['SectionMinEntropy'] <= 7453.500000:
                                                    if sample['DirectoryEntryImport'] <= 5.500000:
                                                        if sample['SizeOfImage'] <= 30.000000:
                                                            if sample['DirectoryEntryExport'] <= 65.500000:
                                                                if sample['AddressOfEntryPoint'] <= 123.000000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['AddressOfEntryPoint'] <= 143.500000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['SectionsLength'] <= 3.500000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            if sample['SectionMinVirtualsize'] <= 241.000000:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                            else:
                                                                                if sample['DllCharacteristics'] <= 36.000000:
                                                                                    return 1  # 0: Benign, 1: Malware
                                                                                else:
                                                                                    return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['SectionMaxPhysical'] <= 3320.500000:
                                                                if sample['MajorImageVersion'] <= 0.500000:
                                                                    if sample['SectionMinVirtualsize'] <= 630.500000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['ImageDirectoryEntryResource'] <= 30.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['DirectoryEntryImport'] <= 6.500000:
                                                            if sample['SectionMinEntropy'] <= 76.500000:
                                                                if sample['SectionMaxPointerData'] <= 368.500000:
                                                                    if sample['SizeOfImage'] <= 114.500000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['CheckSum'] <= 10523.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SizeOfImage'] <= 157.000000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['SectionMaxPointerData'] <= 2395.000000:
                                                                if sample['DllCharacteristics'] <= 49.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SizeOfCode'] <= 1347.000000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['CheckSum'] <= 10574.000000:
                                                                            if sample['AddressOfEntryPoint'] <= 8439.000000:
                                                                                return 0  # 0: Benign, 1: Malware
                                                                            else:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SectionMinVirtualsize'] <= 109.500000:
                                                                    return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['SectionsLength'] <= 1.500000:
                                                        return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SizeOfStackReserve'] <= 10.000000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['DirectoryEntryImportSize'] <= 333.000000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                        else:
                                            if sample['AddressOfEntryPoint'] <= 9.000000:
                                                if sample['SectionMaxVirtual'] <= 15.500000:
                                                    if sample['DirectoryEntryExport'] <= 16.500000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['MajorLinkerVersion'] <= 9.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['SectionMaxPhysical'] <= 2784.000000:
                                                        if sample['e_lfanew'] <= 30.000000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                else:
                                    if sample['SectionMinVirtualsize'] <= 8.500000:
                                        if sample['DllCharacteristics'] <= 33.500000:
                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            if sample['SectionMaxVirtual'] <= 351.500000:
                                                return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['CheckSum'] <= 11032.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                    else:
                                        return 1  # 0: Benign, 1: Malware
                            else:
                                if sample['SectionMaxVirtual'] <= 68.000000:
                                    return 0  # 0: Benign, 1: Malware
                                else:
                                    if sample['SectionMinEntropy'] <= 3860.500000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['SectionMinVirtualsize'] <= 301.500000:
                                if sample['MajorImageVersion'] <= 7.000000:
                                    if sample['SectionMaxPhysical'] <= 10027.500000:
                                        if sample['MinorOperatingSystemVersion'] <= 2.500000:
                                            if sample['SectionMaxPhysical'] <= 617.000000:
                                                if sample['MinorOperatingSystemVersion'] <= 0.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['MajorSubsystemVersion'] <= 2.000000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['MinorSubsystemVersion'] <= 1.500000:
                                                        if sample['SectionMaxVirtual'] <= 57.500000:
                                                            if sample['DirectoryEntryImportSize'] <= 52.500000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SizeOfUninitializedData'] <= 6.500000:
                                                                    if sample['NumberOfSections'] <= 4.500000:
                                                                        if sample['CheckSum'] <= 3325.500000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['SizeOfImage'] <= 252.000000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SectionMinVirtualsize'] <= 172.000000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['e_lfanew'] <= 28.500000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['DirectoryEntryImportSize'] <= 150.000000:
                                                            if sample['ImageDirectoryEntryExport'] <= 2950.000000:
                                                                if sample['e_lfanew'] <= 27.000000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['ImageDirectoryEntryImport'] <= 2669.500000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['AddressOfEntryPoint'] <= 6495.500000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                            else:
                                if sample['MajorOperatingSystemVersion'] <= 3.500000:
                                    if sample['SectionMaxPointerData'] <= 502.000000:
                                        if sample['ImageBase'] <= 99.000000:
                                            if sample['TimeDateStamp'] <= 498.000000:
                                                if sample['SectionMaxPointerData'] <= 132.500000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                            else:
                                                return 1  # 0: Benign, 1: Malware
                                        else:
                                            if sample['SectionsLength'] <= 3.500000:
                                                return 0  # 0: Benign, 1: Malware
                                            else:
                                                return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['TimeDateStamp'] <= 1741.000000:
                                            if sample['MajorLinkerVersion'] <= 7.500000:
                                                if sample['SuspiciousImportFunctions'] <= 5.000000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['BaseOfCode'] <= 45.000000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['TimeDateStamp'] <= 1522.000000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                else:
                                    if sample['MajorLinkerVersion'] <= 9.500000:
                                        if sample['DirectoryEntryImportSize'] <= 202.000000:
                                            if sample['SizeOfInitializedData'] <= 82.000000:
                                                if sample['SizeOfCode'] <= 17.500000:
                                                    if sample['SizeOfInitializedData'] <= 27.000000:
                                                        return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                            else:
                                                return 0  # 0: Benign, 1: Malware
                                        else:
                                            if sample['e_lfanew'] <= 28.500000:
                                                if sample['DirectoryEntryImport'] <= 10.000000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                            else:
                                                return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['ImageBase'] <= 244.500000:
                                            if sample['MajorOperatingSystemVersion'] <= 4.500000:
                                                if sample['SectionMaxVirtual'] <= 31.000000:
                                                    if sample['MajorSubsystemVersion'] <= 3.500000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['SectionMinRawsize'] <= 33.500000:
                                                        if sample['SizeOfCode'] <= 1036.500000:
                                                            if sample['DirectoryEntryImportSize'] <= 69.500000:
                                                                if sample['SizeOfImage'] <= 69.000000:
                                                                    return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['ImageDirectoryEntryExport'] <= 1380.000000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['ImageDirectoryEntryImport'] <= 5647.000000:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SizeOfCode'] <= 122.000000:
                                                    if sample['MajorImageVersion'] <= 0.500000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['Subsystem'] <= 1.500000:
                                                        if sample['ImageDirectoryEntryImport'] <= 5076.000000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                        else:
                                            if sample['CheckSum'] <= 4577.500000:
                                                return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SizeOfCode'] <= 928.000000:
                                                    if sample['MajorSubsystemVersion'] <= 4.500000:
                                                        if sample['ImageBase'] <= 593.000000:
                                                            return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                    else:
                        if sample['ImageBase'] <= 42.500000:
                            if sample['SizeOfCode'] <= 644.500000:
                                if sample['SectionMaxPointerData'] <= 977.000000:
                                    return 1  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
                        else:
                            return 0  # 0: Benign, 1: Malware
                else:
                    if sample['MajorOperatingSystemVersion'] <= 4.500000:
                        if sample['SectionMinVirtualsize'] <= 3688.500000:
                            if sample['CheckSum'] <= 10673.500000:
                                if sample['ImageDirectoryEntryException'] <= 301.000000:
                                    if sample['e_lfanew'] <= 32.500000:
                                        if sample['TimeDateStamp'] <= 10720.500000:
                                            if sample['Subsystem'] <= 1.500000:
                                                if sample['ImageDirectoryEntryExport'] <= 1443.000000:
                                                    if sample['SectionMinRawsize'] <= 65.500000:
                                                        if sample['MajorSubsystemVersion'] <= 3.500000:
                                                            if sample['ImageDirectoryEntryImport'] <= 8209.000000:
                                                                if sample['SizeOfCode'] <= 77.500000:
                                                                    if sample['MajorLinkerVersion'] <= 6.500000:
                                                                        if sample['TimeDateStamp'] <= 1955.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            if sample['SizeOfInitializedData'] <= 377.000000:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                            else:
                                                                                if sample['SectionMaxVirtual'] <= 116.500000:
                                                                                    if sample['SizeOfUninitializedData'] <= 1.500000:
                                                                                        return 1  # 0: Benign, 1: Malware
                                                                                    else:
                                                                                        return 0  # 0: Benign, 1: Malware
                                                                                else:
                                                                                    return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['SizeOfImage'] <= 80.500000:
                                                                            if sample['SectionMaxPointerData'] <= 78.000000:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                            else:
                                                                                if sample['MajorImageVersion'] <= 2.500000:
                                                                                    return 0  # 0: Benign, 1: Malware
                                                                                else:
                                                                                    return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['TimeDateStamp'] <= 1616.000000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SectionMaxPhysical'] <= 8534.000000:
                                                                        if sample['SizeOfCode'] <= 479.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['DirectoryEntryImportSize'] <= 165.500000:
                                                                if sample['Machine'] <= 1.500000:
                                                                    if sample['MinorSubsystemVersion'] <= 0.500000:
                                                                        if sample['ImageDirectoryEntryResource'] <= 5.000000:
                                                                            if sample['SectionMaxPointerData'] <= 227.000000:
                                                                                return 0  # 0: Benign, 1: Malware
                                                                            else:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['AddressOfEntryPoint'] <= 2811.000000:
                                                                        if sample['DirectoryEntryExport'] <= 0.500000:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SectionMaxPhysical'] <= 2309.000000:
                                                                    return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SectionMaxPointerData'] <= 118.500000:
                                                                        if sample['SectionMaxVirtual'] <= 543.500000:
                                                                            if sample['SizeOfImage'] <= 619.500000:
                                                                                if sample['SectionMaxPointerData'] <= 117.000000:
                                                                                    if sample['CheckSum'] <= 6325.000000:
                                                                                        return 1  # 0: Benign, 1: Malware
                                                                                    else:
                                                                                        return 0  # 0: Benign, 1: Malware
                                                                                else:
                                                                                    return 1  # 0: Benign, 1: Malware
                                                                            else:
                                                                                return 0  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['SuspiciousImportFunctions'] <= 19.500000:
                                                        if sample['DirectoryEntryImport'] <= 6.500000:
                                                            if sample['SectionMaxPhysical'] <= 6202.000000:
                                                                if sample['DirectoryEntryImportSize'] <= 112.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SectionMinRawsize'] <= 89.500000:
                                                                        if sample['Characteristics'] <= 71.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            if sample['SectionMaxPhysical'] <= 4247.000000:
                                                                                return 0  # 0: Benign, 1: Malware
                                                                            else:
                                                                                return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['SizeOfCode'] <= 754.500000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['e_lfanew'] <= 28.500000:
                                                    if sample['ImageDirectoryEntrySecurity'] <= 587.000000:
                                                        if sample['SectionMinEntropy'] <= 1970.000000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['TimeDateStamp'] <= 4598.000000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['DllCharacteristics'] <= 47.500000:
                                                                    return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['SectionMaxPhysical'] <= 6636.000000:
                                                            return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                        else:
                                            if sample['DirectoryEntryImportSize'] <= 72.500000:
                                                return 1  # 0: Benign, 1: Malware
                                            else:
                                                if sample['TimeDateStamp'] <= 10996.500000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['DirectoryEntryExport'] <= 10.500000:
                                            if sample['CheckSum'] <= 10289.500000:
                                                if sample['ImageDirectoryEntryImport'] <= 2603.500000:
                                                    if sample['MinorOperatingSystemVersion'] <= 0.500000:
                                                        if sample['ImageDirectoryEntrySecurity'] <= 218.500000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['SectionMinEntropy'] <= 3798.500000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['DllCharacteristics'] <= 49.500000:
                                                        if sample['SizeOfStackCommit'] <= 2.000000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['ImageDirectoryEntryResource'] <= 45.000000:
                                                                if sample['SizeOfInitializedData'] <= 88.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['e_lfanew'] <= 33.500000:
                                                            return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            if sample['SectionMinVirtualsize'] <= 3225.000000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SectionMinVirtualsize'] <= 3287.000000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['ImageDirectoryEntrySecurity'] <= 1182.000000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                        else:
                                            if sample['MajorOperatingSystemVersion'] <= 3.500000:
                                                if sample['e_cp'] <= 2.500000:
                                                    if sample['ImageDirectoryEntryResource'] <= 61.500000:
                                                        return 0  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SectionMaxPointerData'] <= 978.000000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['DirectoryEntryImportSize'] <= 95.500000:
                                                        if sample['ImageDirectoryEntryExport'] <= 3000.000000:
                                                            return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 1  # 0: Benign, 1: Malware
                                else:
                                    if sample['AddressOfEntryPoint'] <= 8715.500000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                            else:
                                if sample['e_lfanew'] <= 32.500000:
                                    if sample['SizeOfInitializedData'] <= 1911.500000:
                                        if sample['ImageDirectoryEntryResource'] <= 88.500000:
                                            if sample['ImageDirectoryEntryExport'] <= 710.500000:
                                                if sample['SizeOfCode'] <= 69.500000:
                                                    if sample['ImageDirectoryEntrySecurity'] <= 1587.000000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['ImageDirectoryEntrySecurity'] <= 3086.000000:
                                                        if sample['SectionMaxVirtual'] <= 113.000000:
                                                            if sample['DllCharacteristics'] <= 47.500000:
                                                                return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['SectionMaxPointerData'] <= 404.500000:
                                                                    return 1  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['SizeOfImage'] <= 185.500000:
                                                            return 0  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                            else:
                                                return 0  # 0: Benign, 1: Malware
                                        else:
                                            if sample['TimeDateStamp'] <= 10706.500000:
                                                if sample['NumberOfSections'] <= 7.500000:
                                                    if sample['TimeDateStamp'] <= 10190.500000:
                                                        if sample['ImageDirectoryEntryImport'] <= 1613.500000:
                                                            if sample['SectionMaxVirtual'] <= 93.500000:
                                                                return 0  # 0: Benign, 1: Malware
                                                            else:
                                                                if sample['MinorImageVersion'] <= 0.500000:
                                                                    if sample['SectionMaxVirtual'] <= 402.000000:
                                                                        return 1  # 0: Benign, 1: Malware
                                                                    else:
                                                                        if sample['ImageDirectoryEntryImport'] <= 1612.000000:
                                                                            return 1  # 0: Benign, 1: Malware
                                                                        else:
                                                                            return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        if sample['MinorOperatingSystemVersion'] <= 0.500000:
                                                            if sample['DirectoryEntryExport'] <= 0.500000:
                                                                if sample['SectionMinVirtualsize'] <= 3222.500000:
                                                                    return 0  # 0: Benign, 1: Malware
                                                                else:
                                                                    if sample['SectionMaxVirtual'] <= 306.000000:
                                                                        return 0  # 0: Benign, 1: Malware
                                                                    else:
                                                                        return 1  # 0: Benign, 1: Malware
                                                            else:
                                                                return 1  # 0: Benign, 1: Malware
                                                        else:
                                                            return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                            else:
                                                return 0  # 0: Benign, 1: Malware
                                    else:
                                        if sample['SectionMinEntropy'] <= 5314.500000:
                                            if sample['e_lfanew'] <= 24.500000:
                                                return 1  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SectionsLength'] <= 3.500000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                                else:
                                    if sample['TimeDateStamp'] <= 10527.500000:
                                        if sample['SectionMaxVirtual'] <= 162.000000:
                                            return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['SectionMaxPhysical'] <= 9623.000000:
                                if sample['SectionMinVirtualsize'] <= 3694.000000:
                                    return 0  # 0: Benign, 1: Malware
                                else:
                                    return 1  # 0: Benign, 1: Malware
                            else:
                                if sample['SizeOfStackCommit'] <= 3.000000:
                                    return 0  # 0: Benign, 1: Malware
                                else:
                                    return 1  # 0: Benign, 1: Malware
                    else:
                        if sample['Characteristics'] <= 45.000000:
                            if sample['SuspiciousImportFunctions'] <= 1.000000:
                                if sample['SectionMaxChar'] <= 37.500000:
                                    if sample['SectionMinRawsize'] <= 45.500000:
                                        if sample['AddressOfEntryPoint'] <= 3252.500000:
                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                                    else:
                                        if sample['MajorSubsystemVersion'] <= 4.500000:
                                            if sample['SectionMinVirtualsize'] <= 1559.000000:
                                                return 1  # 0: Benign, 1: Malware
                                            else:
                                                return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                else:
                                    return 1  # 0: Benign, 1: Malware
                            else:
                                if sample['TimeDateStamp'] <= 441.000000:
                                    if sample['ImageDirectoryEntryResource'] <= 143.500000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                                else:
                                    return 1  # 0: Benign, 1: Malware
                        else:
                            if sample['SectionMinEntropy'] <= 7701.500000:
                                if sample['SectionMinVirtualsize'] <= 2652.500000:
                                    if sample['MajorLinkerVersion'] <= 9.500000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['MinorSubsystemVersion'] <= 0.500000:
                                            if sample['Machine'] <= 1.500000:
                                                if sample['SectionMaxPointerData'] <= 1984.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['DirectoryEntryImport'] <= 7.500000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['MajorLinkerVersion'] <= 12.500000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                                else:
                                    if sample['MinorImageVersion'] <= 0.500000:
                                        return 0  # 0: Benign, 1: Malware
                                    else:
                                        if sample['Characteristics'] <= 62.000000:
                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                            else:
                                return 1  # 0: Benign, 1: Malware
        else:
            if sample['SizeOfInitializedData'] <= 12.000000:
                if sample['ImageDirectoryEntryResource'] <= 82.500000:
                    if sample['SizeOfInitializedData'] <= 9.500000:
                        if sample['SectionMaxVirtual'] <= 47.500000:
                            if sample['Characteristics'] <= 41.500000:
                                return 1  # 0: Benign, 1: Malware
                            else:
                                if sample['AddressOfEntryPoint'] <= 2055.500000:
                                    return 0  # 0: Benign, 1: Malware
                                else:
                                    if sample['AddressOfEntryPoint'] <= 2250.000000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['SectionMaxPhysical'] <= 1821.500000:
                                            if sample['SectionMinEntropy'] <= 116.500000:
                                                return 1  # 0: Benign, 1: Malware
                                            else:
                                                if sample['ImageDirectoryEntryImport'] <= 924.500000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    if sample['TimeDateStamp'] <= 5844.500000:
                                                        return 1  # 0: Benign, 1: Malware
                                                    else:
                                                        return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['SizeOfInitializedData'] <= 8.000000:
                                if sample['SizeOfImage'] <= 87.500000:
                                    return 0  # 0: Benign, 1: Malware
                                else:
                                    return 1  # 0: Benign, 1: Malware
                            else:
                                if sample['ImageDirectoryEntryImport'] <= 3658.000000:
                                    if sample['SizeOfCode'] <= 78.000000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                                else:
                                    if sample['ImageDirectoryEntryImport'] <= 4877.500000:
                                        return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                    else:
                        if sample['SectionMinEntropy'] <= 125.000000:
                            if sample['SizeOfImage'] <= 52.000000:
                                return 0  # 0: Benign, 1: Malware
                            else:
                                if sample['TimeDateStamp'] <= 4708.500000:
                                    return 1  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['ImageBase'] <= 33.000000:
                                if sample['DllCharacteristics'] <= 60.500000:
                                    if sample['SectionMaxPhysical'] <= 4793.000000:
                                        if sample['MajorLinkerVersion'] <= 9.500000:
                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                                    else:
                                        if sample['SectionMaxVirtual'] <= 83.000000:
                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            return 0  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
                else:
                    if sample['Subsystem'] <= 1.500000:
                        return 1  # 0: Benign, 1: Malware
                    else:
                        if sample['ImageDirectoryEntrySecurity'] <= 2082.000000:
                            if sample['SectionMaxPointerData'] <= 707.500000:
                                if sample['Characteristics'] <= 38.500000:
                                    return 1  # 0: Benign, 1: Malware
                                else:
                                    if sample['ImageBase'] <= 33.000000:
                                        if sample['SizeOfCode'] <= 574.500000:
                                            if sample['SectionMaxPhysical'] <= 6209.500000:
                                                return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['SectionMaxVirtual'] <= 102.000000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['TimeDateStamp'] <= 7618.500000:
                                            return 0  # 0: Benign, 1: Malware
                                        else:
                                            if sample['SizeOfImage'] <= 148.500000:
                                                return 0  # 0: Benign, 1: Malware
                                            else:
                                                if sample['MajorLinkerVersion'] <= 19.500000:
                                                    return 1  # 0: Benign, 1: Malware
                                                else:
                                                    return 0  # 0: Benign, 1: Malware
                            else:
                                if sample['SizeOfInitializedData'] <= 9.500000:
                                    if sample['SectionMaxPhysical'] <= 8399.000000:
                                        if sample['SizeOfCode'] <= 927.500000:
                                            return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 0  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['DllCharacteristics'] <= 60.500000:
                                return 1  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
            else:
                if sample['Characteristics'] <= 63.000000:
                    if sample['MajorSubsystemVersion'] <= 4.500000:
                        if sample['TimeDateStamp'] <= 5782.000000:
                            return 1  # 0: Benign, 1: Malware
                        else:
                            if sample['SizeOfImage'] <= 187.000000:
                                if sample['SectionMaxPhysical'] <= 3497.000000:
                                    return 1  # 0: Benign, 1: Malware
                                else:
                                    if sample['SectionMaxVirtual'] <= 65.000000:
                                        if sample['TimeDateStamp'] <= 8449.000000:
                                            return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                    else:
                                        if sample['MajorLinkerVersion'] <= 9.500000:
                                            return 1  # 0: Benign, 1: Malware
                                        else:
                                            if sample['SectionMinRawsize'] <= 33.500000:
                                                if sample['TimeDateStamp'] <= 8265.000000:
                                                    return 0  # 0: Benign, 1: Malware
                                                else:
                                                    return 1  # 0: Benign, 1: Malware
                                            else:
                                                return 1  # 0: Benign, 1: Malware
                            else:
                                return 1  # 0: Benign, 1: Malware
                    else:
                        if sample['MajorLinkerVersion'] <= 19.500000:
                            if sample['SectionMinRawsize'] <= 60.500000:
                                return 1  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['ImageDirectoryEntryResource'] <= 31.500000:
                                return 1  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
                else:
                    if sample['ImageDirectoryEntryResource'] <= 39.000000:
                        if sample['SectionMaxPhysical'] <= 3191.500000:
                            if sample['SectionMaxPointerData'] <= 126.500000:
                                return 0  # 0: Benign, 1: Malware
                            else:
                                if sample['SizeOfImage'] <= 74.000000:
                                    return 1  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['TimeDateStamp'] <= 9032.500000:
                                if sample['SectionMaxPointerData'] <= 197.000000:
                                    return 0  # 0: Benign, 1: Malware
                                else:
                                    return 1  # 0: Benign, 1: Malware
                            else:
                                return 1  # 0: Benign, 1: Malware
                    else:
                        if sample['SectionMinEntropy'] <= 15.000000:
                            return 1  # 0: Benign, 1: Malware
                        else:
                            if sample['MajorSubsystemVersion'] <= 4.000000:
                                if sample['ImageBase'] <= 33.000000:
                                    if sample['Characteristics'] <= 71.000000:
                                        if sample['SizeOfImage'] <= 153.500000:
                                            return 0  # 0: Benign, 1: Malware
                                        else:
                                            return 1  # 0: Benign, 1: Malware
                                    else:
                                        return 1  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
    else:
        if sample['TimeDateStamp'] <= 5118.000000:
            if sample['SectionMaxVirtual'] <= 486.000000:
                if sample['DirectoryEntryExport'] <= 195.000000:
                    return 1  # 0: Benign, 1: Malware
                else:
                    return 0  # 0: Benign, 1: Malware
            else:
                if sample['SizeOfCode'] <= 1399.000000:
                    return 1  # 0: Benign, 1: Malware
                else:
                    return 0  # 0: Benign, 1: Malware
        else:
            if sample['SectionMinRawsize'] <= 28.500000:
                if sample['SizeOfStackReserve'] <= 11.500000:
                    if sample['Characteristics'] <= 80.000000:
                        return 0  # 0: Benign, 1: Malware
                    else:
                        return 1  # 0: Benign, 1: Malware
                else:
                    if sample['DllCharacteristics'] <= 32.500000:
                        return 1  # 0: Benign, 1: Malware
                    else:
                        return 0  # 0: Benign, 1: Malware
            else:
                if sample['DllCharacteristics'] <= 7.000000:
                    return 1  # 0: Benign, 1: Malware
                else:
                    if sample['MinorImageVersion'] <= 4.000000:
                        return 0  # 0: Benign, 1: Malware
                    else:
                        if sample['ImageBase'] <= 33.000000:
                            if sample['DirectoryEntryImport'] <= 12.500000:
                                return 1  # 0: Benign, 1: Malware
                            else:
                                return 0  # 0: Benign, 1: Malware
                        else:
                            if sample['SectionMaxChar'] <= 37.500000:
                                return 0  # 0: Benign, 1: Malware
                            else:
                                if sample['MinorOperatingSystemVersion'] <= 1.500000:
                                    return 1  # 0: Benign, 1: Malware
                                else:
                                    return 0  # 0: Benign, 1: Malware
