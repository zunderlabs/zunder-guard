/** Public schema authority; private previous JSON is read only as data. */
import {readFile,lstat} from 'node:fs/promises';
import {parseReleasePin} from './repo-release-schema.ts';
const read=async(file:string)=>{
  const info=await lstat(file);
  if(!info.isFile()||info.isSymbolicLink()||info.size>=2_000_000)throw new Error('Pin data shape refused');
  return parseReleasePin(JSON.parse(await readFile(file,'utf8')));
};
export async function compare(nextFile:string,previousFile:string){
  const next=await read(nextFile);
  let before;
  try{before=await read(previousFile);}catch(e:any){if(e.code!=='ENOENT')throw e;return;}
  const a=next.version.split('.').map(Number),b=before.version.split('.').map(Number);
  const change=a[0]-b[0]||a[1]-b[1]||a[2]-b[2];
  if(change<0)throw new Error('Website release downgrade refused');
  if(change===0&&before.published){
    if(next.sourceCommit!==before.sourceCommit||next.releaseId!==before.releaseId
      ||next.signedAssetManifest.sha256!==before.signedAssetManifest.sha256)throw new Error('Same-version replacement refused');
    for(const name of ['unixInstallerUrl','windowsInstallerUrl','awsTemplateUrl','homebrewReady'] as const)
      if(before.channels[name]&&next.channels[name]!==before.channels[name])throw new Error('Same-version channel regression refused');
  }
}
if(process.argv[1]?.endsWith('/repo-compare-pin.ts')){
  if(process.argv.length!==4)throw new Error('Require next/previous JSON data paths');
  await compare(process.argv[2]!,process.argv[3]!);
}
