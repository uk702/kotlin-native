/*
 * Copyright 2010-2017 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jetbrains.kotlin.backend.konan.library.impl

import org.jetbrains.kotlin.backend.konan.library.KonanLibraryReader
import org.jetbrains.kotlin.backend.konan.serialization.deserializeModule
import org.jetbrains.kotlin.konan.file.File
import org.jetbrains.kotlin.konan.properties.*
import org.jetbrains.kotlin.config.LanguageVersionSettings
import org.jetbrains.kotlin.konan.target.KonanTarget

class LibraryReaderImpl(var libraryFile: File, val currentAbiVersion: Int, val target: KonanTarget? = null) : KonanLibraryReader {

    // For the zipped libraries inPlace gives files from zip file system
    // whereas realFiles extracts them to /tmp.
    // For unzipped libraries inPlace and realFiles are the same
    // providing files in the library directory.
    private val inPlace = KonanLibrary(libraryFile, target)
    private val realFiles = inPlace.realFiles

    private val reader = MetadataReaderImpl(inPlace)

    val manifestProperties: Properties by lazy {
        inPlace.manifestFile.loadProperties()
    }

    val abiVersion: String
        get() {
            val manifestAbiVersion = manifestProperties.getProperty("abi_version")
            if ("$currentAbiVersion" != manifestAbiVersion) 
                error("ABI version mismatch. Compiler expects: $currentAbiVersion, the library is $manifestAbiVersion")
            return manifestAbiVersion
        }

    val targetList = inPlace.targetsDir.listFiles.map{it.name}

    override val libraryName 
        get() = inPlace.libraryName

    override val bitcodePaths: List<String>
        get() = (realFiles.kotlinDir.listFiles + realFiles.nativeDir.listFiles).map{it.absolutePath}

    override val linkerOpts: List<String>
        get() = manifestProperties.propertyList("linkerOpts", target!!.targetSuffix)

    val moduleHeaderData: ByteArray by lazy {
        reader.loadSerializedModule()
    }

    fun packageMetadata(fqName: String): ByteArray =
        reader.loadSerializedPackageFragment(fqName)

    override fun moduleDescriptor(specifics: LanguageVersionSettings) 
        = deserializeModule(specifics, {packageMetadata(it)}, moduleHeaderData)

}

