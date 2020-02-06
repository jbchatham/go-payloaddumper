package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/xi2/xz"
	"hash"
	"io"
	"log"
	"os"
)

const (
	PAYLOAD_MAGIC = "CrAU"
)

var ERR_INVALID_FORMAT_BAD_MAGIC = errors.New("Invalid payload format, bad magic")

type payloadHeader struct {
	magic                 [4]byte
	fileFormatVersion     uint64
	manifestSize          uint64
	metaDataSignatureSize uint32
}

func (header *payloadHeader) String() string {
	return fmt.Sprintf("Header version %d, manifest size %d, metadata signature size: %d",
		header.fileFormatVersion,
		header.manifestSize,
		header.metaDataSignatureSize)
}

type payloadDumper struct {
	payloadFile       *os.File
	outputDir         string
	version           uint64
	archiveManifest   *DeltaArchiveManifest
	metaDataSignature *Signatures
	dataOffset        int64
}

func NewPayloadDumper(fileName string) (pd *payloadDumper, err error) {
	pd = &payloadDumper{}
	if pd.payloadFile, err = os.Open(fileName); err != nil {
		return
	}
	header := payloadHeader{}

	if err = binary.Read(pd.payloadFile, binary.BigEndian, &header.magic); err != nil {
		return
	}
	if PAYLOAD_MAGIC != string(header.magic[:]) {
		err = ERR_INVALID_FORMAT_BAD_MAGIC
		return
	}
	if err = binary.Read(pd.payloadFile, binary.BigEndian, &header.fileFormatVersion); err != nil {
		err = fmt.Errorf("Error reading payload, failed to read version: %v", err)
		return
	}
	if err = binary.Read(pd.payloadFile, binary.BigEndian, &header.manifestSize); err != nil {
		err = fmt.Errorf("Error reading payload, failed to read manifest size: %v", err)
		return
	}

	// for now, only handle the partition (version 2) format
	if header.fileFormatVersion != 2 {
		err = fmt.Errorf("Invalid payload version %d, only version 2 currently supported", header.fileFormatVersion)
	}

	if header.fileFormatVersion >= 2 {
		if err = binary.Read(pd.payloadFile, binary.BigEndian, &header.metaDataSignatureSize); err != nil {
			err = fmt.Errorf("Error reading payload, failed to read manifest data signature size: %v", err)
			return
		}
	}

	//log.Printf("Opening payload file %s, header info %s", fileName, header.String())

	// decode the DeltaArchiveManifest
	buf := make([]byte, header.manifestSize)
	if err = binary.Read(pd.payloadFile, binary.BigEndian, &buf); err != nil {
		err = fmt.Errorf("Error reading payload, failed to read manifest: %v", err)
		return
	}

	pd.archiveManifest = &DeltaArchiveManifest{}
	if err = proto.Unmarshal(buf, pd.archiveManifest); err != nil {
		err = fmt.Errorf("Error reading payload, failed to decode manifest: %v", err)
		return
	}

	//log.Printf("Read archive manifest: %s", pd.archiveManifest.String())
	if header.metaDataSignatureSize > 0 {
		// decode the Signatures
		buf = make([]byte, header.metaDataSignatureSize)
		if err = binary.Read(pd.payloadFile, binary.BigEndian, &buf); err != nil {
			err = fmt.Errorf("Error reading payload, failed to read metadata signature: %v", err)
			return
		}

		pd.metaDataSignature = &Signatures{}
		if err = proto.Unmarshal(buf, pd.metaDataSignature); err != nil {
			err = fmt.Errorf("Error reading payload, failed to decode metadata signature: %v", err)
			return
		}
	}

	// TODO, sanity check signatures before returning

	// everything else done on the return
	pd.version = header.fileFormatVersion

	// theoretically the immediate next should be data
	pd.dataOffset, err = pd.payloadFile.Seek(0, os.SEEK_CUR)
	if err != nil {
		err = fmt.Errorf("Error reading payload, failed to record offset of data start: %v", err)
		return
	}

	return
}

func (pd *payloadDumper) performInstallOperation(output io.Writer, iop *InstallOperation, readBuf *bytes.Buffer) (err error) {
	readStart := int64(iop.GetDataOffset())
	readSize := int64(iop.GetDataLength())
	//log.Printf("Performing install operation: %v, data start %d, read offset %d, read start: %d, read size %d", iop.GetType(), pd.dataOffset, readStart, int64(readStart) + pd.dataOffset, readSize)
	// reset buf
	readBuf.Reset()
	// seek to start
	_, err = pd.payloadFile.Seek(pd.dataOffset+readStart, 0)
	if err != nil {
		err = fmt.Errorf("Failed to seek to install operation start: %v", err)
		return
	}

	// if there's a data hash, setup to hash data on read
	var srcDataReader io.Reader
	var hasher hash.Hash
	if iop.GetDataSha256Hash() != nil && len(iop.GetDataSha256Hash()) > 0 {
		hasher = sha256.New()
		srcDataReader = io.TeeReader(pd.payloadFile, hasher)
	} else {
		srcDataReader = io.Reader(pd.payloadFile)
	}

	// read the expected data
	bytesRead, err := io.CopyN(readBuf, srcDataReader, readSize)
	if err != nil {
		err = fmt.Errorf("Failed to read install operation: %v", err)
		return
	}
	if bytesRead != readSize {
		err = fmt.Errorf("Read %d bytes, expecting %d", bytesRead, readSize)
		return
	}

	// if there was a data hash, validate 
	if hasher != nil {
		dataSum := hasher.Sum(nil)
		if bytes.Compare(dataSum, iop.GetDataSha256Hash()) != 0 {
			err = fmt.Errorf("SHA256 failed for operation, expected %s, calculated %s", hex.EncodeToString(iop.GetDataSha256Hash()), hex.EncodeToString(dataSum))
			return
		}
	}

	iopReader := io.Reader(bytes.NewReader(readBuf.Bytes()))
	switch iop.GetType() {
	case InstallOperation_REPLACE_XZ:
		iopReader, err = xz.NewReader(iopReader, 0)
		if err != nil {
			err = fmt.Errorf("Failed to decode XZ stream: %v", err)
			return
		}
	case InstallOperation_REPLACE_BZ:
		iopReader = bzip2.NewReader(iopReader)
	case InstallOperation_REPLACE:
		// nothing to do
	default:
		err = fmt.Errorf("Unimplemented install operation type: %v", iop.GetType())
		return
	}

	if iopReader != nil {
		_, err = io.Copy(output, iopReader)
		if err != nil {
			err = fmt.Errorf("Error copying install operation to output file: %v", err)
			return
		}
		//log.Printf("%d bytes copied to output file", bytesCopied)
	}

	return
}

func (pd *payloadDumper) dumpPartition(pu *PartitionUpdate, readBuf *bytes.Buffer) (err error) {
	outputFileName := pd.outputDir + string(os.PathSeparator) + pu.GetPartitionName() + ".img"
	log.Printf("Dumping partition '%s' to file %s", pu.GetPartitionName(), outputFileName)
	// TODO, check for file and don't overwrite unless specified
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		err = fmt.Errorf("Failed to create output file %s: %v", outputFileName, err)
		return
	}
	defer outputFile.Close()
	output := bufio.NewWriter(outputFile)
	defer output.Flush()
	for _, io := range pu.GetOperations() {
		// TODO, convert this to a goroutine?  Will need to sync around the file read/writes, but the decompression seems to be single threaded
		// right now, so might gain a little benefit.. if nothing else, interesting exercise..
		err = pd.performInstallOperation(output, io, readBuf)
		if err != nil {
			err = fmt.Errorf("Failed to dump partition '%s': %v", pu.GetPartitionName(), err)
			return
		}
		fmt.Print(".")
	}
	fmt.Print("\n")

	return
}

func (pd *payloadDumper) dumpV2() (err error) {
	log.Printf("Payload contains %d partitions", len(pd.archiveManifest.Partitions))
	// figure out the largest # of blocks we're going to be dumping.. we'll create one buffer and reuse
	var largestBlockCount uint64
	for _, pu := range pd.archiveManifest.Partitions {
		for _, io := range pu.GetOperations() {
			for _, e := range io.GetDstExtents() {
				if e.GetNumBlocks() > largestBlockCount {
					largestBlockCount = e.GetNumBlocks()
				}
			}
		}
	}
	readBuf := bytes.NewBuffer(make([]byte, largestBlockCount*uint64(pd.archiveManifest.GetBlockSize())))
	//log.Printf("Created buffer of size %d to read largest extent block count of %d", readBuf.Cap(), largestBlockCount)
	for _, pu := range pd.archiveManifest.Partitions {
		err = pd.dumpPartition(pu, readBuf)
		if err != nil {
			return
		}
	}
	return
}

func main() {
	var payloadFile, outputDir string

	flag.StringVar(&payloadFile, "file", "", "payload filename")
	flag.StringVar(&outputDir, "outdir", ".", "output directory")
	flag.Parse()

	if payloadFile == "" {
		flag.PrintDefaults()
		log.Fatal("Payload file not specified")
	}

	dumper, err := NewPayloadDumper(payloadFile)
	if dumper.payloadFile != nil {
		defer dumper.payloadFile.Close()
	}
	if err != nil {
		log.Fatalf("Failed to open payload file %s: %v", payloadFile, err)
	}
	dumper.outputDir = outputDir
	log.Printf("Detected payload version %d", dumper.version)
	switch dumper.version {
	case 2:
		err = dumper.dumpV2()
	default:
		log.Fatalf("Payload version %d not handled yet", dumper.version)
	}
	if err != nil {
		log.Fatalf("Failed to dump payload: %v", err)
	}
}
