import { useState, useEffect, useRef } from 'react'
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { SignifyClient, ready } from "signify-ts";
import { SignifyDemo } from './SignifyDemo';

function generateRandomKey() {
    const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const length = 21;
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

export function Signify() {
    const [pre, setPre] = useState("")
    const [icp, setICP] = useState("")
    const [key, setKey] = useState(generateRandomKey())
    const [response, setResponse] = useState("")



    useEffect(() => {
        ready().then(() => {
            console.log("signify client is ready")
        })
    }, [])

    const inputRef = useRef(null)

    useEffect(() => {
        if (inputRef.current) {
            inputRef.current.style.width = "auto"
            inputRef.current.style.width = `${inputRef.current.scrollWidth}px`
        }
    }, [key])

    return (
        <>
            <div className="card">
                {/* show kel*/}
                <div className="form">
                    <label htmlFor="key">Enter 21 character passcode:</label>
                    <input type="text" id="key" value={key} onChange={(e) => setKey(e.target.value)} ref={inputRef} className="button" />
                </div>
                <p >
                    Client AID is {pre}
                </p>
                {/* show kel*/}
                <SignifyDemo text={'Agent State'}
                    onClick={async () => {
                        const client = new SignifyClient("http://localhost:3901", key)
                        setPre(client.controller.pre)
                        try {
                            await client.state()
                        }
                        catch (e) {
                            console.log(e)
                            await client.boot()
                        }
                        let res = await client.state()
                        let resp = JSON.stringify(res, null, 2)
                        return resp
                    }} />
                <SignifyDemo text={'Get identifiers'}
                    onClick={async () => {
                        try {
                            const client = new SignifyClient("http://localhost:3901", key)
                            setPre(client.controller.pre)
                            try{
                                await client.connect()
                            }
                            catch(e){
                                console.log('error connecting', e)
                                console.log('booting up')
                                await client.boot()
                                await client.connect()
                                console.log('booted and connected up')
                            }
                            let res = await client.identifiers()
                            console.log("IDENTIFIER CLASS", res)
                            let resp = await res.list_identifiers()
                            console.log("IDENTIFIER response", JSON.stringify(resp))
                            return JSON.stringify(resp)
                        }
                        catch (e) {
                            console.log(e)
                            return 'Error getting identifiers'
                        }
                    }} />
            </div>
        </>
    )
}


