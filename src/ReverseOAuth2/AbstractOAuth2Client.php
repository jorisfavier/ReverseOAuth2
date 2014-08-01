<?php

namespace ReverseOAuth2;

use Zend\Http\PhpEnvironment\Request;
use Zend\Session\Container;
use ReverseOAuth2\ClientOptions;
use ReverseOAuth2\OAuht2HttpClient;

abstract class AbstractOAuth2Client
{
    
    /**
     * @var Container
     */
    protected $session;
    
    /**
     * @var ClientOptions
     */
    protected $options;
    
    protected $error;
    
    /**
     * @var OAuth2HttpClient
     */
    protected $httpClient;

    abstract public function getUrl();
    
    abstract public function getToken(Request $request);
    
    public function __construct()
    {
        $this->session = new Container('ReverseOAuth2_'.get_class($this));
    }
    
    public function getInfo($newInfo=false)
    {
        if(is_object($this->session->info) && !$newInfo) {
            
            return $this->session->info;
        
        } elseif(isset($this->session->token->access_token)) {
            
            if(!strpos($this->options->getInfoUri(), "?")){
                $urlProfile = $this->options->getInfoUri() . '?access_token='.$this->session->token->access_token;
            }
            else{
                $urlProfile = $this->options->getInfoUri() . '&access_token='.$this->session->token->access_token;
            }

            $client = $this->getHttpclient()
                            ->resetParameters(true)
                            ->setHeaders(array('Accept-encoding' => 'http', 'Cache-Control' => 'no-cache, must-revalidate'))
                            ->setMethod(Request::METHOD_GET)
                            ->setUri($urlProfile);
            
            $retVal = $client->send()->getContent();
            $contentType = $client->send()->getHeaders()->get("Content-Type")->getFieldValue();
            if(strlen(trim($retVal)) > 0 && (strpos($contentType,"text") > 0 || strpos($contentType,"text")===0) ) {
                $this->session->info = \Zend\Json\Decoder::decode($retVal);
                return $this->session->info;
                
            } else if($contentType=="image/jpeg") {
                return $retVal;

            } else {
                
                $this->error = array('internal-error' => 'Get info return value is empty.');
                return false;
                
            }
            
        } else {
            
            $this->error = array('internal-error' => 'Session access token not found.');
            return false;
            
        }
    }
    
    public function getScope($glue = ' ')
    {
        if(is_array($this->options->getScope()) AND count($this->options->getScope()) > 0) {
            $str = urlencode(implode($glue, array_unique($this->options->getScope())));
            return '&scope=' . $str;
        } else {
            return '';
        }
    }
    
    public function getState()
    {
        return $this->session->state;
    }
    
    protected function generateState()
    {
        $this->session->state = md5(microtime().'-'.get_class($this));
        return $this->session->state;
    }
    
    public function setOptions(ClientOptions $options)
    {
        $this->options = $options;
    }
    
    public function getOptions()
    {
        return $this->options;
    }
    
    public function getError()
    {
        return $this->error;
    }
    
    public function getSessionToken()
    {
        return $this->session->token;
    }
    
    public function getSessionContainer()
    {
        return $this->session;
    }
    
    public function getProvider()
    {
        return $this->providerName;
    }
    
    public function setHttpClient($client)
    {
        if($client instanceof OAuth2HttpClient) {
            $this->httpClient = $client;
        } else {
            throw new Exception\HttpClientException('Passed HTTP client is not supported.');
        }
    }
    
    public function getHttpClient()
    {
        $connOptions = array(
            'timeout' => 30,
            //'adapter' => '\Zend\Http\Client\Adapter\Curl'
        );
        $connOptions['adapter'] = $this->options->getConnAdapter();
        $connOptionsConf = $this->options->getConnOpts();
        if (is_array($connOptionsConf) && count($connOptionsConf) > 0) {
            $connOptions['curloptions'] = $connOptionsConf;
        }

        if(!$this->httpClient) {
            $this->httpClient = new OAuth2HttpClient(null, $connOptions);
        }

        return $this->httpClient;
        
    }
    
}
