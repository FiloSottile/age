param([switch]$release=$false)
if($args.count -ne 0){
    echo "no"
}
$AV=git describe --tags
$AV=$AV -split '-\d*-g'
$AGE_VER=$av[0].Substring(1,$AV[0].length-1)

if($release.IsPresent -or $AV.length -eq 1){
    $verstring="`"-X main.version=$AGE_VER`""

} else {
    $verstring="`"-X main.version=$AGE_VER -X main.commit=$AV[1]`""
}
go build --ldflags $verstring -o . filippo.io/age/cmd/...
if($?){
    echo "build success"
} else {
    echo "build failed"
}

