param([switch] $release = $false)

if($args.count -ne 0){
    Write-Output "Usage: ./build_age.ps1 [-release]"
    exit 1
}

$AV=git describe --tags
$AV=$AV -split '-\d*-g'
$AGE_VER=$av[0]
# -release doesn't use a hash to allow for minor post-tag commits (e.g. README updates) without having to revert or retag
if($release.IsPresent){
    $verstring="`"-X main.version=$AGE_VER`""
} else{
    $verstring="`"-X main.version=$AGE_VER -X main.commit=$($AV[1])`""
}

go build --ldflags $verstring -o . filippo.io/age/cmd/...

if($?){
    Write-Output "build success"
} else{
    Write-Output "build failure"
    exit 1
}

