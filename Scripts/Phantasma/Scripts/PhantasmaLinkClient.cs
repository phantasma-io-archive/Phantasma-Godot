using System;
using System.Collections;
using System.Numerics;
using System.Collections.Generic;

using LunarLabs.Parser;
using LunarLabs.Parser.JSON;

using NativeWebSocket;
using Godot;
using Phantasma;

public class PhantasmaLinkClient
{
    public struct Balance 
    {
        public readonly string symbol;
        public readonly BigInteger value;
        public readonly int decimals;

        public Balance(string symbol, BigInteger value, int decimals)
        {
            this.symbol = symbol;
            this.value = value;
            this.decimals = decimals;
        }
    }

    public static PhantasmaLinkClient Instance { get; private set; }

    public string DappID = "demo";

    public string Host = "localhost:7090";
    public int GasPrice = 100000;

    public CanvasGroup ModalTarget;

    private WebSocket websocket;

    private Text _messageObj;

    public bool Ready { get; private set; }

    public bool Enabled { get; private set; }

    public bool Busy { get; private set; }

    public string Nexus { get; private set; }
    public string Wallet { get; private set; }
    public string Token { get; private set; }
    public string Name { get; private set; }
    public string Address { get; private set; }

    public Texture2D Avatar { get; private set; }

    public IEnumerable<string> Assets => _balanceMap.Keys;

    private Dictionary<int, Action<DataNode>> _requestCallbacks = new Dictionary<int, Action<DataNode>>();

    private Dictionary<string, Balance> _balanceMap = new Dictionary<string, Balance>();

    void Awake()
    {
        Instance = this;

        var bgObj = ModalTarget.GetComponent<RectTransform>();
        //bgObj.sizeDelta = new Vector2(Screen.width, Screen.height);

        var temp = ModalTarget.transform.Find("Message");
        _messageObj = temp.GetComponent<Text>();
        _messageObj.text = "Loading...";

        var rt = temp.GetComponent<RectTransform>();
        rt.sizeDelta = new Vector2(Screen.width, Screen.height);

        SetModal(false);
    }

    public async void Enable()
    {
        if (Enabled)
        {
            return;
        }

        this.Enabled = true;

        if (ModalTarget == null)
        {
            GD.PrintErr("Please assign Modal target in inspector...");
            return;
        }

        this.Wallet = "Unknown";
        this.Token = null;

        websocket = new WebSocket($"ws://{Host}/phantasma");

        websocket.OnOpen += () =>
        {
            this.Ready = true;
            GD.Print("Connection open!");
        };

        websocket.OnError += (e) =>
        {
            GD.Print("Error! " + e);
        };

        websocket.OnClose += (e) =>
        {
            GD.Print("Connection closed!");
        };

        websocket.OnMessage += (bytes) =>
        {
            // getting the message as a json string
            var json = System.Text.Encoding.UTF8.GetString(bytes);
            GD.Print("OnMessage! " + json);

            var node = JSONReader.ReadFromString(json);

            var reqID = node.GetInt32("id");
            if (_requestCallbacks.ContainsKey(reqID))
            {
                var callback = _requestCallbacks[reqID];
                _requestCallbacks.Remove(reqID);

                callback(node);
            }
            else
            {
                GD.Print("Got weird request with id " + reqID);
            }
        };

        // waiting for messages
        await websocket.Connect();
    }

    void Update()
    {
        if (!Enabled)
        {
            return;
        }

#if !UNITY_WEBGL || UNITY_EDITOR
        websocket?.DispatchMessageQueue();
#endif
    }

    /*async void SendWebSocketMessage()
    {
        if (websocket.State == WebSocketState.Open)
        {
            // Sending bytes
            await websocket.Send(new byte[] { 10, 20, 30 });

            // Sending plain text
            await websocket.SendText("plain text message");
        }
    }*/

    private async void OnApplicationQuit()
    {
        if (websocket != null)
        {
            await websocket.Close();
        }
    }

    private void FetchAccount(Action<bool> callback)
    {
        ShowModal("Authorized, obtaining account info...");

        SendLinkRequest("getAccount", (result) =>
        {
            HideModal();

            var success = result.GetBool("success");
            if (success)
            {
                var avatarData = result.GetString("avatar");
                avatarData = avatarData.Split(new char[] { ',' }, 2)[1];

                var avatarBytes = System.Convert.FromBase64String(avatarData);

                this.Avatar = new Texture2D(32, 32, TextureFormat.ARGB32, false, true);                
                ImageConversion.LoadImage(this.Avatar, avatarBytes);

                GD.Print($"Avatar: {Avatar.width}x{Avatar.height}");

                //GD.Print($"result: {result} | -> platform: {result.GetString("platform")} | -> external: {result.GetString("external")}");
                //this.Nexus = result.GetString("nexus");
                this.Name = result.GetString("name");
                this.Address = result.GetString("address");

                _balanceMap.Clear();

                var balances = result.GetNode("balances");
                foreach (var child in balances.Children)
                {
                    var symbol = child.GetString("symbol");
                    var value = child.GetString("value");
                    var decimals = child.GetInt32("decimals");

                    var amount = BigInteger.Parse(value);
                    _balanceMap[symbol] = new Balance(symbol, amount, decimals);
                }

                callback(true);
            }
            else
            {
                callback(false);
            }
        });
    }

    private int requestID;

    private void SetModal(bool enabled)
    {
        Busy = enabled;
        ModalTarget.alpha = enabled ? 1: 0;
    }

    private void ShowModal(string msg)
    {
        _messageObj.text = msg;
        SetModal(true);
    }

    private void HideModal()
    {
        SetModal(false);
    }

    private async void SendLinkRequest(string request, Action<DataNode> callback)
    {
        if (this.Token != null)
        {
            request = request + '/' + this.DappID + '/' + this.Token;
        }

        requestID++;

        request = $"{requestID},{request}";

        _requestCallbacks[requestID] = callback;
        GD.Print("Request=>" + request);

        await websocket.SendText(request);
    }

    #region PUBLIC INTERFACE

    public decimal GetBalance(string symbol)
    {
        if (_balanceMap.ContainsKey(symbol))
        {
            var temp = _balanceMap[symbol];
            return UnitConversion.ToDecimal(temp.value, temp.decimals);
        }

        return 0;
    }

    public void Login(Action<bool> callback)
    {
        ShowModal("Connection established, authorizing...");

        SendLinkRequest($"authorize/{DappID}", (result) =>
        {
            var success = result.GetBool("success");
            if (success)
            {
                var connectedNexus = result.GetString("nexus");
                if (connectedNexus != this.Nexus) this.Nexus = connectedNexus;
                this.Wallet = result.GetString("wallet");
                this.Token = result.GetString("token");
                FetchAccount(callback);
            }
            else
            {
                HideModal();
                callback(false);
            }
        });
    }

    public void SendTransaction(string chain, byte[] script, byte[] payload, Action<Hash, string> callback)
    {
        ShowModal("Relaying transaction...");

        if (script.Length >= 8192)
        {
            callback(Hash.Null, "script too big");
            return; 
        }

        var hexScript = Base16.Encode(script);
        var hexPayload = payload != null && payload.Length > 0 ?  Base16.Encode(payload) : ""; // is empty string for payload ok?

        SendLinkRequest($"signTx/{this.Nexus}/{chain}/{hexScript}/{hexPayload}", (result) =>
        {
            HideModal();
            var success = result.GetBool("success");
            if (success)
            {
                var hashStr = result.GetString("hash");
                var hash = Hash.Parse(hashStr);
                callback(hash, null);
            }
            else
            {
                var msg = result.GetString("message");
                callback(Hash.Null, "transaction rejected: "+ msg);
            }
        });
    }

    #endregion
}
