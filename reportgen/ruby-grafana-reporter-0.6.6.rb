# MIT License
# 
# Copyright (c) 2020 Christian Kohlmeyer
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESs
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# frozen_string_literal: true

require 'rubygems'
require 'rubygems/ext'
require 'net/http'
require 'fileutils'
require 'yaml'
require 'socket'
require 'uri'
require 'json'
require 'tempfile'
require 'cgi'
require 'optparse'
require 'date'
require 'time'
require 'logger'
require 'asciidoctor'
require 'asciidoctor/extensions'
require 'asciidoctor-pdf'
require 'zip'

folders = [
  %w[grafana],
  %w[grafana_reporter logger],
  %w[grafana_reporter],
  %w[grafana_reporter asciidoctor extensions],
  %w[grafana_reporter asciidoctor],
  %w[grafana_reporter erb],
  %w[grafana_reporter application]
]

# frozen_string_literal: true

# Version information
GRAFANA_REPORTER_VERSION = [0, 6, 6].freeze
# Release date
GRAFANA_REPORTER_RELEASE_DATE = '2024-02-22'

# frozen_string_literal: true

module Grafana
  # This abstract class defines the base functionalities for the common datasource implementations.
  # Additionally it provides a factory method to build a real datasource from a given specification.
  class AbstractDatasource
    attr_reader :model

    @@subclasses = []

    # Registers the subclass as datasource.
    # @param subclass [Class] class inheriting from this abstract class
    def self.inherited(subclass)
      @@subclasses << subclass
    end

    # Overwrite this method, to specify if the current datasource implementation handles the given model.
    # This method is called by {build_instance} to determine, if the current datasource implementation
    # can handle the given grafana model. By default this method returns false.
    # @param model [Hash] grafana specification of the datasource to check
    # @return [Boolean] True if fits, false otherwise
    def self.handles?(model)
      false
    end

    # Factory method to build a datasource from a given datasource Hash description.
    # @param ds_model [Hash] grafana specification of a single datasource
    # @return [AbstractDatasource] instance of a fitting datasource implementation
    def self.build_instance(ds_model)
      raise InvalidDatasourceQueryProvidedError, ds_model unless ds_model.is_a?(Hash)

      raise InvalidDatasourceQueryProvidedError, ds_model unless ds_model['meta'].is_a?(Hash)

      @@subclasses.each do |datasource_class|
        return datasource_class.new(ds_model) if datasource_class.handles?(ds_model)
      end

      UnsupportedDatasource.new(ds_model)
    end

    def initialize(model)
      @model = model
    end

    # @return [String] category of the datasource, e.g. +tsdb+ or +sql+
    def category
      @model['meta']['category']
    end

    # @return [String] type of the datasource, e.g. +mysql+
    def type
      @model['type'] || @model['meta']['id']
    end

    # @return [String] name of the datasource
    def name
      @model['name']
    end

    # @return [String] unique ID of the datasource
    def uid
      @model['uid']
    end

    # @return [Integer] ID of the datasource
    def id
      @model['id'].to_i
    end

    # @abstract
    #
    # Executes a request for the current database with the given options.
    #
    # Used format of the response will always be the following:
    #
    #   {
    #     :header => [column_title_1, column_title_2],
    #     :content => [
    #                   [row_1_column_1, row_1_column_2],
    #                   [row_2_column_1, row_2_column_2]
    #                 ]
    #   }
    #
    # @param query_description [Hash] query description, which will requested:
    # @option query_description [String] :grafana_version grafana version, for which the request is to be prepared
    # @option query_description [String] :from +from+ timestamp
    # @option query_description [String] :to +to+ timestamp
    # @option query_description [Integer] :timeout expected timeout for the request
    # @option query_description [WebRequest] :prepared_request prepared web request for relevant {Grafana} instance, if this is needed by datasource
    # @option query_description [String] :raw_query raw query, which shall be executed. May include variables, which will be replaced before execution
    # @option query_description [Hash<Variable>] :variables hash of variables, which can potentially be replaced in the given +:raw_query+
    # @return [Hash] sql result formatted as stated above
    def request(query_description)
      raise NotImplementedError
    end

    # @abstract
    #
    # The different datasources supported by grafana use different ways to store the query in the
    # panel's JSON model. This method extracts a query from that description, that can be used
    # by the {AbstractDatasource} implementation of the datasource.
    #
    # @param panel_query_target [Hash] grafana panel target, which contains the query description
    # @return [String] query string, which can be used as +raw_query+ in a {#request}
    def raw_query_from_panel_model(panel_query_target)
      raise NotImplementedError
    end

    # @abstract
    #
    # Overwrite in subclass, to specify the default variable format during replacement of variables.
    # @return [String] default {Variable#value_formatted} format
    def default_variable_format
      raise NotImplementedError
    end

    # Replaces the grafana variables in the given string with their replacement value.
    #
    # @param string [String] string in which the variables shall be replaced
    # @param variables [Hash<String,Variable>] Hash containing the variables, which shall be replaced in the
    #  given string
    # @param overwrite_default_format [String] {Variable#value_formatted} value, if a custom default format should be used, otherwise {#default_variable_format} is used as default, which may be overwritten
    # @return [String] string in which all variables are properly replaced
    def replace_variables(string, variables, overwrite_default_format = nil)
      res = string
      repeat = true
      repeat_count = 0

      # TODO: find a proper way to replace variables recursively instead of over and over again
      # TODO: add tests for recursive replacement of variable
      while repeat && (repeat_count < 3)
        repeat = false
        repeat_count += 1

        variables.each do |name, variable|
          # do not replace with non grafana variables
          next unless name =~ /^var-/

          # only set ticks if value is string
          var_name = name.gsub(/^var-/, '')
          next unless var_name =~ /^\w+$/

          res = res.gsub(/(?:\$\{#{var_name}(?::(?<format>\w+))?\}|\$#{var_name}(?!\w))/) do
            format = overwrite_default_format
            format = default_variable_format if overwrite_default_format.nil?
            if $LAST_MATCH_INFO
              format = $LAST_MATCH_INFO[:format] if $LAST_MATCH_INFO[:format]
            end
            variable.value_formatted(format)
          end
        end
        repeat = true if res.include?('$')
      end

      res
    end

    private

    # Provides a general method to handle the given query response as general Grafana Dataframe format.
    #
    # This method throws {UnsupportedQueryResponseReceivedError} if the given query response is not a
    # properly formattes dataframe
    #
    # @param response_body [String] raw response body
    def preformat_dataframe_response(response_body)
      json = JSON.parse(response_body)
      data = json['results'].values.first

      # TODO: check how multiple frames have to be handled
      data = data['frames']
      headers = []

      data.first['schema']['fields'].each do |headline|
        use_name_only = true
        if not headline['config'].nil?
          if not headline['config']['displayNameFromDS'].nil?
            use_name_only = false
          end
        end
        header = use_name_only ? headline['name'] : headline['config']['displayNameFromDS']
        headers << header
      end

      # zip all result values together, so that we have one complete table
      content = data.first['data']['values'][0].zip(*data.first['data']['values'][1..])
      return { header: headers, content: content }

    rescue
      raise UnsupportedQueryResponseReceivedError, response_body
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Representation of one specific dashboard in a {Grafana} instance.
  class Dashboard
    # @return [Grafana] parent {Grafana} object
    attr_reader :grafana
    attr_reader :panels, :variables

    # @param model [Hash] converted JSON Hash of the grafana dashboard
    # @param grafana [Grafana] parent {Grafana} object
    def initialize(model, grafana)
      @grafana = grafana
      @model = model

      init_panels
      init_variables
    end

    # @return [String] +from+ time configured in the dashboard.
    def from_time
      return @model['time']['from'] if @model['time']

      nil
    end

    # @return [String] +to+ time configured in the dashboard.
    def to_time
      @model['time']['to'] if @model['time']
      nil
    end

    # @return [String] dashboard UID
    def id
      @model['uid']
    end

    # @return [String] dashboard title
    def title
      @model['title']
    end

    # @return [Panel] panel for the specified ID
    def panel(id)
      panels = @panels.select { |item| item.field('id') == id.to_i }
      raise PanelDoesNotExistError.new(id, self) if panels.empty?

      panels.first
    end

    private

    # store variables in array as objects of type Variable
    def init_variables
      @variables = []
      return unless @model.key?('templating')

      list = @model['templating']['list']
      return unless list.is_a? Array

      list.each do |item|
        begin
          @variables << Variable.new(item, self)
        rescue => e
          # TODO: show this message as a warning - needs test cleanup
          @grafana.logger.debug(e.message)
        end
      end
    end

    # read panels
    def init_panels
      @panels = []
      return unless @model.key?('panels')

      @model['panels'].each do |panel|
        if panel.key?('panels')
          panel['panels'].each do |subpanel|
            @panels << Panel.new(subpanel, self)
          end
        else
          @panels << Panel.new(panel, self)
        end
      end
    end
  end
end

# frozen_string_literal: true

module Grafana
  # A top level alarm for all other errors in current module.
  class GrafanaError < StandardError
    def initialize(message)
      super("GrafanaError: #{message} (#{self.class})")
    end
  end

  # Raised if a given dashboard does not exist in a specific {Grafana} instance.
  class DashboardDoesNotExistError < GrafanaError
    # @param dashboard_uid [String] dashboard uid, which could not be found
    def initialize(dashboard_uid)
      super("The specified dashboard '#{dashboard_uid}' does not exist.")
    end
  end

  # Raised if a given panel does not exist on a specific {Dashboard} in the current {Grafana} instance.
  class PanelDoesNotExistError < GrafanaError
    # @param panel_id [String] panel id, which could not be found on the dashboard
    # @param dashboard [Dashboard] dashboard object on which the panel could not be found
    def initialize(panel_id, dashboard)
      super("The specified panel id '#{panel_id}' does not exist on the dashboard '#{dashboard.id}'.")
    end
  end

  # Raised if a given query letter does not exist on a specific {Panel}.
  class QueryLetterDoesNotExistError < GrafanaError
    # @param query_letter [String] query letter name, which could not be found on the panel
    # @param panel [Panel] panel object on which the query could not be found
    def initialize(query_letter, panel)
      super("The specified query '#{query_letter}' does not exist in the panel '#{panel.id}' "\
        "in dashboard '#{panel.dashboard}'.")
    end
  end

  # Raised if a given datasource does not exist in a specific {Grafana} instance.
  class DatasourceDoesNotExistError < GrafanaError
    # @param field [String] specifies, how the datasource has been searched, e.g. +id+ or +name+
    # @param datasource_identifier [String] identifier of the datasource, which could not be found,
    #   e.g. the specified id or name
    def initialize(field, datasource_identifier)
      super("Datasource with #{field} '#{datasource_identifier}' does not exist.")
    end
  end

  # Raised if a {Panel} could not be rendered as an image.
  #
  # Most likely this happens, because the image renderer is not configures properly in grafana,
  # or the panel rendering ran into a timeout.
  # @param panel [Panel] panel object, which could not be rendered
  class ImageCouldNotBeRenderedError < GrafanaError
    def initialize(panel)
      super("The specified panel '#{panel.id}' from dashboard '#{panel.dashboard.id}' could not be "\
        'rendered to an image. Check if rendering is possible manually by selecting "Share" and then '\
        '"Direct link rendered image" from a panel\'s options menu.')
    end
  end

  # Raised if no SQL query is specified.
  class MissingSqlQueryError < GrafanaError
    def initialize
      super('No SQL statement has been specified.')
    end
  end

  # Raised if a datasource shall be queried, which is not (yet) supported by the reporter
  class InvalidDatasourceQueryProvidedError < GrafanaError
    def initialize(query)
      super("The datasource query provided, does not look like a grafana datasource target (received: #{query}).")
    end
  end

  # Raised if a datasource query returned with an unsupported result
  class UnsupportedQueryResponseReceivedError < GrafanaError
    def initialize(response)
      super("The datasource request returned with an unsupported response format (received: #{response}).")
    end
  end
end

# frozen_string_literal: true

# Contains all objects for creating structured objects for interfacing grafana.
#
# The intention is, that these represent the business logic contained within grafana
# in an appropriate object model for the reporter to work with.
#
# For details, see also {https://grafana.com/docs/grafana/latest/http_api Grafana API}.
module Grafana
  # Main class for handling the interaction with one specific Grafana instance.
  class Grafana
    attr_reader :logger

    # @param base_uri [String] full URI pointing to the specific grafana instance without
    #   trailing slash, e.g. +https://localhost:3000+.
    # @param key [String] API key for the grafana instance, if required
    # @param opts [Hash] additional options.
    #   Currently supporting +:logger+.
    def initialize(base_uri, key = nil, opts = {})
      @base_uri = base_uri
      @key = key
      @dashboards = {}
      @logger = opts[:logger] || ::Logger.new(nil)

      initialize_datasources unless @base_uri.empty?
    end

    # @return [Hash] Information about the current organization
    def organization
      return @organization if @organization

      response = prepare_request({ relative_url: '/api/org/' }).execute
      if response.is_a?(Net::HTTPOK)
        @organization = JSON.parse(response.body)
      end

      @organization
    end

    # @return [String] grafana version
    def version
      return @version if @version

      response = prepare_request({ relative_url: '/api/health' }).execute
      if response.is_a?(Net::HTTPOK)
        @version = JSON.parse(response.body)['version']
      end

      @version
    end

    # Used to test a connection to the grafana instance.
    #
    # Running this function also determines, if the API configured here has Admin or NON-Admin privileges,
    # or even fails on connecting to grafana.
    #
    # @return [String] +Admin+, +NON-Admin+ or +Failed+ is returned, depending on the test results
    def test_connection
      if prepare_request({ relative_url: '/api/datasources' }).execute.is_a?(Net::HTTPOK)
        # we have admin rights
        @logger.warn('Reporter is running with Admin privileges on grafana. This is a potential security risk.')
        return 'Admin'
      end
      # check if we have lower rights
      return 'Failed' unless prepare_request({ relative_url: '/api/dashboards/home' }).execute.is_a?(Net::HTTPOK)

      @logger.info('Reporter is running with NON-Admin privileges on grafana.')
      'NON-Admin'
    end

    # Returns the datasource, which has been queried by the datasource name.
    #
    # @param datasource_name [String] name of the searched datasource
    # @return [Datasource] Datasource for the specified datasource name
    def datasource_by_name(datasource_name)
      datasource_name = 'default' if datasource_name.to_s.empty?
      # TODO: PRIO add support for grafana builtin datasource types
      return UnsupportedDatasource.new(nil) if datasource_name.to_s =~ /-- (?:Mixed|Dashboard|Grafana) --/
      raise DatasourceDoesNotExistError.new('name', datasource_name) unless @datasources[datasource_name]

      @datasources[datasource_name]
    end

    # Returns the datasource, which has been queried by the datasource uid.
    #
    # @param datasource_uid [String] unique id of the searched datasource
    # @return [Datasource] Datasource for the specified datasource unique id
    def datasource_by_uid(datasource_uid)
      clean_nil_datasources
      datasource = @datasources.select { |ds_name, ds| ds.uid == datasource_uid }.values.first
      raise DatasourceDoesNotExistError.new('uid', datasource_uid) unless datasource

      datasource
    end

    # Returns the datasource, which has been queried by the datasource id.
    #
    # @param datasource_id [Integer] id of the searched datasource
    # @return [Datasource] Datasource for the specified datasource id
    def datasource_by_id(datasource_id)
      clean_nil_datasources
      datasource = @datasources.select { |name, ds| ds.id == datasource_id.to_i }.values.first
      raise DatasourceDoesNotExistError.new('id', datasource_id) unless datasource

      datasource
    end

    # @return [Array] Array of dashboard uids within the current grafana object
    def dashboard_ids
      response = prepare_request({ relative_url: '/api/search' }).execute
      return [] unless response.is_a?(Net::HTTPOK)

      dashboards = JSON.parse(response.body)

      dashboards.each do |dashboard|
        @dashboards[dashboard['uid']] = nil unless @dashboards[dashboard['uid']]
      end

      @dashboards.keys
    end

    # @param dashboard_uid [String] UID of the searched {Dashboard}
    # @return [Dashboard] dashboard object, if it has been found
    def dashboard(dashboard_uid)
      return @dashboards[dashboard_uid] unless @dashboards[dashboard_uid].nil?

      response = prepare_request({ relative_url: "/api/dashboards/uid/#{dashboard_uid}" }).execute
      raise DashboardDoesNotExistError, dashboard_uid unless response.is_a?(Net::HTTPOK)

      # cache dashboard for reuse
      model = JSON.parse(response.body)['dashboard']
      @dashboards[dashboard_uid] = Dashboard.new(model, self)

      @dashboards[dashboard_uid]
    end

    # Prepares a {WebRequest} object for the current {Grafana} instance, which may be enriched
    # with further properties and can then run {WebRequest#execute}.
    #
    # @option options [Hash] :relative_url relative URL with a leading slash, which shall be queried
    # @option options [Hash] :accept
    # @option options [Hash] :body
    # @option options [Hash] :content_type
    # @return [WebRequest] webrequest prepared for execution
    def prepare_request(options = {})
      auth = @key ? { authorization: "Bearer #{@key}" } : {}
      WebRequest.new(@base_uri, auth.merge({ logger: @logger }).merge(options))
    end

    private

    def initialize_datasources
      @datasources = {}

      settings = prepare_request({ relative_url: '/api/frontend/settings' }).execute
      return unless settings.is_a?(Net::HTTPOK)

      json = JSON.parse(settings.body)
      json['datasources'].select { |_k, v| v['id'].to_i.positive? }.each do |ds_name, ds_value|
        @datasources[ds_name] = AbstractDatasource.build_instance(ds_value)

        # print debug info for https://github.com/divinity666/ruby-grafana-reporter/issues/29
        if @datasources[ds_name].nil?
          @logger.error("Datasource with name '#{ds_name}' and configuration: '#{ds_value}' could not be initialized.")
          @datasources.delete(ds_name)
        end
      end

      @datasources['default'] = @datasources[json['defaultDatasource']] if not @datasources[json['defaultDatasource']].nil?
    end

    def clean_nil_datasources
      @datasources.delete_if do |name, ds|
        if ds.nil?
          # print debug info for https://github.com/divinity666/ruby-grafana-reporter/issues/29
          @logger.warn("Datasource with name #{name} is nil, which should never happen. Check logs for details.")
        end
        ds.nil?
      end
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the datasource interface to grafana alerts.
  class GrafanaAlertsDatasource < AbstractDatasource
    # +:raw_query+ needs to contain a Hash with the following structure:
    #
    #   {
    #     dashboardId: Dashboard ID as String or nil
    #     panelId:     Panel ID as String or nil
    #     columns:
    #     limit:
    #     query:
    #     state:
    #     folderId:
    #     dashboardQuery:
    #     dashboardTag:
    #   }
    # @see AbstractDatasource#request
    def request(query_description)
      webrequest = query_description[:prepared_request]
      webrequest.relative_url = "/api/alerts#{url_parameters(query_description)}"

      result = webrequest.execute(query_description[:timeout])

      json = JSON.parse(result.body)

      content = []
      begin
        json.each { |item| content << item.fetch_values(*query_description[:raw_query]['columns'].split(',')) }
      rescue KeyError => e
        raise MalformedAttributeContentError.new(e.message, 'columns', query_description[:raw_query]['columns'])
      end

      result = {}
      result[:header] = [query_description[:raw_query]['columns'].split(',')]
      result[:content] = content

      result
    end

    private

    def url_parameters(query_desc)
      url_vars = {}
      url_vars.merge!(query_desc[:raw_query].select do |k, _v|
        k =~ /^(?:limit|dashboardId|panelId|query|state|folderId|dashboardQuery|dashboardTag)/
      end)
      url_vars['from'] = query_desc[:from] if query_desc[:from]
      url_vars['to'] = query_desc[:to] if query_desc[:to]
      url_params = URI.encode_www_form(url_vars.map { |k, v| [k, v.to_s] })
      return '' if url_params.empty?

      "?#{url_params}"
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the datasource interface to grafana annotations.
  class GrafanaAnnotationsDatasource < AbstractDatasource
    # +:raw_query+ needs to contain a Hash with the following structure:
    #
    #   {
    #     dashboardId: Dashboard ID as String or nil
    #     panelId:     Panel ID as String or nil
    #     columns:
    #     limit:
    #     alertId:
    #     userId:
    #     type:
    #     tags:
    #   }
    # @see AbstractDatasource#request
    def request(query_description)
      webrequest = query_description[:prepared_request]
      webrequest.relative_url = "/api/annotations#{url_parameters(query_description)}"

      result = webrequest.execute(query_description[:timeout])

      json = JSON.parse(result.body)

      content = []
      begin
        json.each { |item| content << item.fetch_values(*query_description[:raw_query]['columns'].split(',')) }
      rescue KeyError => e
        raise MalformedAttributeContentError.new(e.message, 'columns', query_description[:raw_query]['columns'])
      end

      result = {}
      result[:header] = [query_description[:raw_query]['columns'].split(',')]
      result[:content] = content

      result
    end

    private

    def url_parameters(query_desc)
      url_vars = {}
      url_vars.merge!(query_desc[:raw_query].select do |k, _v|
        k =~ /^(?:limit|alertId|dashboardId|panelId|userId|type|tags)/
      end)
      url_vars['from'] = query_desc[:from] if query_desc[:from]
      url_vars['to'] = query_desc[:to] if query_desc[:to]
      url_params = URI.encode_www_form(url_vars.map { |k, v| [k, v.to_s] })
      return '' if url_params.empty?

      "?#{url_params}"
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements a datasource to return environment related information about the grafana instance in a tabular format.
  class GrafanaEnvironmentDatasource < ::Grafana::AbstractDatasource
    # +:raw_query+ needs to contain a Hash with the following structure:
    #
    #   {
    #     grafana:  {Grafana} object to query
    #     mode:     'general' (default) or 'dashboards' for receiving different environment information
    #   }
    # @see AbstractDatasource#request
    def request(query_description)
      raise MissingSqlQueryError if query_description[:raw_query].nil?
      raw_query = {mode: 'general'}.merge(query_description[:raw_query])

      return dashboards_data(raw_query[:grafana]) if raw_query[:mode] == 'dashboards'

      general_data(raw_query[:grafana])
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
      nil
    end

    # @see AbstractDatasource#name
    def name
      self.class.to_s
    end

    private

    def general_data(grafana)
      {
        header: ['Version', 'Organization Name', 'Organization ID', 'Access permissions'],
        content: [[grafana.version,
                   grafana.organization['name'],
                   grafana.organization['id'],
                   grafana.test_connection]]
      }
    end

    def dashboards_data(grafana)
      content = []
      grafana.dashboard_ids.each do |id|
        content << [id, grafana.dashboard(id).title, grafana.dashboard(id).panels.length]
      end

      {
        header: ['Dashboard ID', 'Dashboard Name', '# Panels'],
        content: content
      }
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the datasource interface to grafana model properties.
  class GrafanaPropertyDatasource < AbstractDatasource
    # +:raw_query+ needs to contain a Hash with the following structure:
    #
    #   {
    #     property_name: Name of the queried property as String
    #     panel:         {Panel} object to query
    #   }
    # @see AbstractDatasource#request
    def request(query_description)
      raise MissingSqlQueryError if query_description[:raw_query].nil?

      panel = query_description[:raw_query][:panel]
      property_name = query_description[:raw_query][:property_name]

      return "Panel property '#{property_name}' does not exist for panel '#{panel.id}'" unless panel.field(property_name)

      {
        header: [query_description[:raw_query][:property_name]],
        content: [replace_variables(panel.field(property_name), query_description[:variables])]
      }
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
      'glob'
    end

    # @see AbstractDatasource#name
    def name
      self.class.to_s
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the interface to graphite datasources.
  class GraphiteDatasource < AbstractDatasource
    # @see AbstractDatasource#handles?
    def self.handles?(model)
      tmp = new(model)
      tmp.type == 'graphite'
    end

    # +:raw_query+ needs to contain a Graphite query as String
    # @see AbstractDatasource#request
    def request(query_description)
      raise MissingSqlQueryError if query_description[:raw_query].nil?

      request = {
        body: URI.encode_www_form('from': DateTime.strptime(query_description[:from], '%Q').strftime('%H:%M_%Y%m%d'),
                                  'until': DateTime.strptime(query_description[:to], '%Q').strftime('%H:%M_%Y%m%d'),
                                  'format': 'json',
                                  'target': replace_variables(query_description[:raw_query], query_description[:variables])),
        content_type: 'application/x-www-form-urlencoded',
        request: Net::HTTP::Post
      }

      webrequest = query_description[:prepared_request]
      webrequest.relative_url = "/api/datasources/proxy/#{id}/render"
      webrequest.options.merge!(request)

      result = webrequest.execute(query_description[:timeout])
      preformat_response(result.body)
    end

    # @see AbstractDatasource#raw_query_from_panel_model
    def raw_query_from_panel_model(panel_query_target)
      panel_query_target['target']
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
        'glob'
    end

    private

    def preformat_response(response_body)
      begin
        return preformat_dataframe_response(response_body)
      rescue
        # TODO: show an info, that the response if not a dataframe
      end

      json = JSON.parse(response_body)
      header = ['time']
      content = {}

      # keep sorting, if json has only one target item, otherwise merge results and return
      # as a time sorted array
      return { header: header << json.first['target'], content: json.first['datapoints'].map! { |item| [item[1], item[0]] } } if json.length == 1

      # TODO: show warning if results may be sorted different
      json.each_index do |i|
        header << json[i]['target']
        tmp = json[i]['datapoints'].map! { |item| [item[1], item[0]] }.to_h
        tmp.each_key { |key| content[key] = Array.new(json.length) unless content[key] }

        content.merge!(tmp) do |_key, old, new|
          old[i] = new
          old
        end
      end

      return { header: header, content: content.to_a.map(&:flatten).sort { |a, b| a[0] <=> b[0] } }

    rescue
      raise UnsupportedQueryResponseReceivedError, response_body
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the interface to image rendering datasources.
  class ImageRenderingDatasource < AbstractDatasource
    # +:raw_query+ needs to contain a Hash with the following structure:
    #
    #   {
    #     panel: {Panel} which shall be rendered
    #   }
    # @see AbstractDatasource#request
    def request(query_description)
      panel = query_description[:raw_query][:panel]

      webrequest = query_description[:prepared_request]
      webrequest.relative_url = panel.render_url + url_params(query_description)
      webrequest.options.merge!({ accept: 'image/png' })

      result = webrequest.execute(query_description[:timeout])

      raise ImageCouldNotBeRenderedError, panel if result.body.include?('<html')

      { header: ['image'], content: [result.body] }
    end

    private

    def url_params(query_desc)
      url_vars = query_desc[:variables].select { |k, _v| k =~ /^(?:timeout|scale|height|width|theme|fullscreen|var-.+)$/ }
      url_vars = default_vars.merge(url_vars)
      url_vars['from'] = Variable.new(query_desc[:from])
      url_vars['to'] = Variable.new(query_desc[:to])
      result = URI.encode_www_form(url_vars.map { |k, v| [k, v.raw_value.to_s] })

      return '' if result.empty?

      "&#{result}"
    end

    def default_vars
      {
        'fullscreen' => Variable.new(true),
        'theme' => Variable.new('light'),
        'timeout' => Variable.new(60)
      }
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the interface to Prometheus datasources.
  class InfluxDbDatasource < AbstractDatasource
    # @see AbstractDatasource#handles?
    def self.handles?(model)
      tmp = new(model)
      tmp.type == 'influxdb'
    end

    # +:database+ needs to contain the InfluxDb database name
    # +:raw_query+ needs to contain a InfluxDb query as String
    # @see AbstractDatasource#request
    def request(query_description)
      raise MissingSqlQueryError if query_description[:raw_query].nil?

      # replace variables
      query = replace_variables(query_description[:raw_query], query_description[:variables])

      # Unfortunately the grafana internal variables are not replaced in the grafana backend, but in the
      # frontend, i.e. we have to replace them here manually
      # replace $timeFilter variable
      query = query.gsub(/\$timeFilter(?=\W|$)/, "time >= #{query_description[:from]}ms and time <= #{query_description[:to]}ms")

      interval = query_description[:variables].delete('interval') || ((query_description[:to].to_i - query_description[:from].to_i) / 1000).to_i
      interval = interval.raw_value if interval.is_a?(Variable)

      # replace grafana variables $__interval and $__interval_ms in query
      # TODO: check where calculation and replacement of interval variable should take place
      query = query.gsub(/\$(?:__)?interval(?=\W|$)/, "#{interval.is_a?(String) ? interval : "#{(interval / 1000).to_i}s"}")
      query = query.gsub(/\$(?:__)?interval_ms(?=\W|$)/, "#{interval}")

      webrequest = query_description[:prepared_request]
      request = {}

      ver = query_description[:grafana_version].split('.').map{|x| x.to_i}
      if ver[0] >= 8
        webrequest.relative_url = "/api/ds/query?ds_type=influxdb"

        request = {
          request: Net::HTTP::Post,
          body: {
            from: query_description[:from],
            to: query_description[:to],
            queries: [
              {
                datasource: {type: "influxdb"},
                datasourceId: id,
                intervalMs: interval,
                query: query
              }
          ]}.to_json
        }
      else
        webrequest.relative_url = "/api/datasources/proxy/#{id}/query?db=#{@model['database']}&q=#{ERB::Util.url_encode(query)}&epoch=ms"
        request = {
          request: Net::HTTP::Get
        }
      end

      webrequest.options.merge!(request)


      result = webrequest.execute(query_description[:timeout])
      preformat_response(result.body)
    end

    # @see AbstractDatasource#raw_query_from_panel_model
    def raw_query_from_panel_model(panel_query_target)
      return panel_query_target['query'] if panel_query_target['query'] or panel_query_target['rawQuery']

      # build composed queries
      build_select(panel_query_target['select']) + build_from(panel_query_target) + build_where(panel_query_target['tags']) + build_group_by(panel_query_target['groupBy'])
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
      'regex'
    end

    private

    def build_group_by(stmt)
      groups = []
      fill = ""

      stmt.each do |group|
        case group['type']
        when 'tag'
          groups << "\"#{group['params'].first}\""

        when 'fill'
          fill = " fill(#{group['params'].first})"

        else
          groups << "#{group['type']}(#{group['params'].join(', ')})"

        end
      end

      " GROUP BY #{groups.join(', ')}#{fill}"
    end

    def build_where(stmt)
      custom_where = []

      stmt.each do |where|
        value = where['operator'] =~ /^[=!]~$/ ? where['value'] : "'#{where['value']}'"
        custom_where << "\"#{where['key']}\" #{where['operator']} #{value}"
      end

      " WHERE #{"(#{custom_where.join(' AND ')}) AND " unless custom_where.empty?}$timeFilter"
    end

    def build_from(stmt)
      " FROM \"#{"stmt['policy']." unless stmt['policy'] == 'default'}#{stmt['measurement']}\""
    end

    def build_select(stmt)
      res = "SELECT"
      parts = []

      stmt.each do |value|
        part = ""

        value.each do |item|
          case item['type']
          when 'field'
            # frame field parameter as string
            part = "\"#{item['params'].first}\""

          when 'alias'
            # append AS with parameter as string
            part = "#{part} AS \"#{item['params'].first}\""


          when 'math'
            # append parameter as raw value for calculation
            part = "#{part} #{item['params'].first}"


          else
            # frame current part by brackets and call by item function including parameters
            part = "#{item['type']}(#{part}#{", #{item['params'].join(', ')}" unless item['params'].empty?})"
          end
        end

        parts << part
      end

      "#{res} #{parts.join(', ')}"
    end

    def preformat_response(response_body)
      begin
        return preformat_dataframe_response(response_body)
      rescue
        # TODO: show an info, that the response if not a dataframe
      end

      # TODO: how to handle multiple query results?
      json = JSON.parse(response_body)
      json = json['results'].first['series']
      return {} if json.nil?

      header = ['time']
      content = {}

      # keep sorting, if json has only one target item, otherwise merge results and return
      # as a time sorted array
      return { header: header << "#{json.first['name']} #{json.first['columns'][1]} (#{json.first['tags']})", content: json.first['values'] } if json.length == 1

      # TODO: show warning here, as results may be sorted different
      json.each_index do |i|
        header << "#{json[i]['name']} #{json[i]['columns'][1]} (#{json[i]['tags']})"
        tmp = json[i]['values'].to_h
        tmp.each_key { |key| content[key] = Array.new(json.length) unless content[key] }

        content.merge!(tmp) do |_key, old, new|
          old[i] = new
          old
        end
      end

      return { header: header, content: content.to_a.map(&:flatten).sort { |a, b| a[0] <=> b[0] } }

    rescue
      raise UnsupportedQueryResponseReceivedError, response_body
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Representation of one specific panel in a {Dashboard} instance.
  class Panel
    # @return [Dashboard] parent {Dashboard} object
    attr_reader :dashboard
    attr_reader :model

    # @param model [Hash] converted JSON Hash of the panel
    # @param dashboard [Dashboard] parent {Dashboard} object
    def initialize(model, dashboard)
      @model = model
      @dashboard = dashboard

      @datasource_uid_or_name = @model['datasource']
      if @model['datasource'].is_a?(Hash)
        @datasource_uid_or_name = @model['datasource']['uid']
      end
    end

    # @return [String] content of the requested field or +''+ if not found
    def field(field)
      return @model[field] if @model.key?(field)

      nil
    end

    # @return [String] panel ID
    def id
      @model['id']
    end

    # This method should always be called before the +datasource+ method of a
    # panel is invoked, to ensure that the variable names in the datasource
    # field are resolved.
    #
    # @param variables [Hash] variables hash, which should be use to resolve variable datasource
    def resolve_variable_datasource(variables)
      @datasource_uid_or_name = AbstractDatasource.new(nil).replace_variables(@datasource_uid_or_name, variables, 'raw') if @datasource_uid_or_name.is_a?(String)
    end

    # @return [Datasource] datasource object specified for the current panel
    def datasource
      if datasource_kind_is_uid?
        dashboard.grafana.datasource_by_uid(@datasource_uid_or_name)
      else
        dashboard.grafana.datasource_by_name(@datasource_uid_or_name)
      end
    end

    # @return [String] query string for the requested query letter
    def query(query_letter)
      query_item = @model['targets'].select { |item| item['refId'].to_s == query_letter.to_s }.first
      raise QueryLetterDoesNotExistError.new(query_letter, self) unless query_item

      datasource.raw_query_from_panel_model(query_item)
    end

    # @return [String] relative rendering URL for the panel, to create an image out of it
    def render_url
      "/render/d-solo/#{@dashboard.id}?panelId=#{@model['id']}"
    end

    private

    def datasource_kind_is_uid?
      if @model['datasource'].is_a?(Hash)
        return true
      end
      false
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the interface to Prometheus datasources.
  class PrometheusDatasource < AbstractDatasource
    # @see AbstractDatasource#handles?
    def self.handles?(model)
      tmp = new(model)
      tmp.type == 'prometheus'
    end

    # +:raw_query+ needs to contain a Prometheus query as String
    # @see AbstractDatasource#request
    def request(query_description)
      raise MissingSqlQueryError if query_description[:raw_query].nil?

      query_hash = query_description[:raw_query].is_a?(Hash) ? query_description[:raw_query] : {}

      # read instant value and convert instant value to boolean value
      instant = query_description[:variables].delete('instant') || query_hash[:instant] || false
      instant = instant.raw_value if instant.is_a?(Variable)
      instant = instant.to_s.downcase == 'true'
      interval = query_description[:variables].delete('interval') || query_hash[:interval] || 15
      interval = interval.raw_value if interval.is_a?(Variable)
      query = query_hash[:query] || query_description[:raw_query]

      ver = query_description[:grafana_version].split('.').map{|x| x.to_i}
      request = nil
      if (ver[0] == 7 and ver[1] < 5) or ver[0] < 7
        request = prepare_get_request({query_description: query_description, instant: instant, interval: interval, query: query})
      else
        request = prepare_post_request({query_description: query_description, instant: instant, interval: interval, query: query})
      end

      result = request.execute(query_description[:timeout])
      preformat_response(result.body)
    end

    # @see AbstractDatasource#raw_query_from_panel_model
    def raw_query_from_panel_model(panel_query_target)
      { query: panel_query_target['expr'], instant: panel_query_target['instant'],
        interval: panel_query_target['step'] }
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
        'regex'
    end

    private
    def prepare_get_request(hash)
      url = if hash[:instant]
        "/api/datasources/proxy/#{id}/api/v1/query?time=#{hash[:query_description][:to]}&query="\
        "#{CGI.escape(replace_variables(hash[:query], hash[:query_description][:variables]))}"
      else
        "/api/datasources/proxy/#{id}/api/v1/query_range?start=#{hash[:query_description][:from]}"\
        "&end=#{hash[:query_description][:to]}"\
        "&query=#{CGI.escape(replace_variables(hash[:query], hash[:query_description][:variables]))}"\
        "&step=#{hash[:interval]}"
      end

      webrequest = hash[:query_description][:prepared_request]
      webrequest.relative_url = url
      webrequest.options.merge!({ request: Net::HTTP::Get })

      webrequest
    end

    def prepare_post_request(hash)
      webrequest = hash[:query_description][:prepared_request]
      webrequest.relative_url = '/api/ds/query'

      params = {
        from: hash[:query_description][:from],
        to: hash[:query_description][:to],
        queries: [{
          datasource: { type: type, uid: uid },
          datasourceId: id,
          exemplar: false,
          expr: hash[:query],
          format: 'time_series',
          interval: '',
          # intervalFactor: ### 2,
          # intervalMs: ### 15000,
          # legendFormat: '', ### {{job}}
          # maxDataPoints: 999,
          metric: '',
          queryType: 'timeSeriesQuery',
          refId: 'A',
          # requestId: '14A',
          # utcOffsetSec: 7200,
          step: hash[:interval]
        }],
        range: {
          #from: ### "2022-07-31T16:19:26.198Z",
          #to: ### "2022-07-31T16:19:26.198Z",
          raw: { from: hash[:query_description][:variables]['from'].raw_value, to: hash[:query_description][:variables]['to'].raw_value }
        }
      }

      webrequest.options.merge!({ request: Net::HTTP::Post, body: params.to_json })

      webrequest
    end

    def preformat_response(response_body)
      # TODO: show raw response body to debug case https://github.com/divinity666/ruby-grafana-reporter/issues/24
      begin
        return preformat_dataframe_response(response_body)
      rescue
        # TODO: show an info, that the response is not a dataframe
      end

      json = JSON.parse(response_body)

      # handle response with error result
      unless json['error'].nil?
        return { header: ['error'], content: [[ json['error'] ]] }
      end

      # handle former result formats
      result_type = json['data']['resultType']
      json = json['data']['result']

      headers = ['time']
      content = {}

      # handle vector queries
      if result_type == 'vector'
        return {
          header: (headers << 'value') + json.first['metric'].keys,
          content: [ [json.first['value'][0], json.first['value'][1]] + json.first['metric'].values ]
        }
      end

      # handle scalar queries
      if result_type =~ /^(?:scalar|string)$/
        return { header: headers << result_type, content: [[json[0], json[1]]] }
      end

      # keep sorting, if json has only one target item, otherwise merge results and return
      # as a time sorted array
      if json.length == 1
        return { header: headers << json.first['metric']['mode'], content: json.first['values'] }
      end

      # TODO: show warning if results may be sorted different
      json.each_index do |i|
        headers += [json[i]['metric']['mode']]
        tmp = json[i]['values'].to_h
        tmp.each_key { |key| content[key] = Array.new(json.length) unless content[key] }

        content.merge!(tmp) do |_key, old, new|
          old[i] = new
          old
        end
      end

      return { header: headers, content: content.to_a.map(&:flatten).sort { |a, b| a[0] <=> b[0] } }

    rescue
      raise UnsupportedQueryResponseReceivedError, response_body
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Implements the interface to all SQL based datasources (tested with PostgreSQL and MariaDB/MySQL).
  class SqlDatasource < AbstractDatasource
    # @see AbstractDatasource#handles?
    def self.handles?(model)
      tmp = new(model)
      tmp.category == 'sql'
    end

    # +:raw_query+ needs to contain a SQL query as String in the respective database dialect
    # @see AbstractDatasource#request
    def request(query_description)
      raise MissingSqlQueryError if query_description[:raw_query].nil?

      sql = replace_variables(query_description[:raw_query], query_description[:variables])
      webrequest = query_description[:prepared_request]
      request = {}

      ver = query_description[:grafana_version].split('.').map{|x| x.to_i}
      if ver[0] >= 8
        webrequest.relative_url = '/api/ds/query'
        request = {
          body: {
            from: query_description[:from],
            to: query_description[:to],
            queries: [{
              datasource: { type: type, uid: uid },
              datasourceId: id,
              rawSql: sql,
              format: 'table',
              # intervalMs: '',
              # maxDataPoints: 999,
              refId: 'A'
            }]
          }.to_json,
          request: Net::HTTP::Post
        }
      else
        webrequest.relative_url = '/api/tsdb/query'
        request = {
          body: {
            from: query_description[:from],
            to: query_description[:to],
            queries: [rawSql: sql, datasourceId: id, format: 'table']
          }.to_json,
          request: Net::HTTP::Post
        }
      end
      webrequest.options.merge!(request)

      result = webrequest.execute(query_description[:timeout])
      preformat_response(result.body)
    end

    # Currently all composed SQL queries are saved in the dashboard as rawSql, so no conversion
    # necessary here.
    # @see AbstractDatasource#raw_query_from_panel_model
    def raw_query_from_panel_model(panel_query_target)
      panel_query_target['rawSql']
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
        'glob'
    end

    private

    def preformat_response(response_body)
      begin
        return preformat_dataframe_response(response_body)
      rescue
        # TODO: show an info, that the response if not a dataframe
      end

      results = {}
      results.default = []
      results[:header] = []
      results[:content] = []

      JSON.parse(response_body)['results'].each_value do |query_result|
        if query_result.key?('error')
          results[:header] = results[:header] + ['SQL Error']
          results[:content] = [[query_result['error']]]

        elsif query_result.key?('tables')
          if query_result['tables']
            query_result['tables'].each do |table|
              results[:header] = results[:header] + table['columns'].map { |header| header['text'] }
              results[:content] = table['rows']
            end
          end
        end
      end

      return results

    rescue
      raise UnsupportedQueryResponseReceivedError, response_body
    end
  end
end

# frozen_string_literal: true

module Grafana
  # Dummy class, which is used, if a datasource is currently unsupported.
  class UnsupportedDatasource < AbstractDatasource
  end
end

# frozen_string_literal: true

module Grafana
  # This class contains a representation of
  # {https://grafana.com/docs/grafana/latest/variables/templates-and-variables grafana variables},
  # aka grafana templates.
  #
  # The main need therefore rises in order to replace variables properly in different
  # texts, e.g. SQL statements or results.
  class Variable
    attr_reader :name, :text, :raw_value

    # Translation table to support {https://momentjs.com/docs/#/displaying/}.
    DATE_MATCHES = { 'M' => '%-m', 'MM' => '%m', 'MMM' => '%b',  'MMMM' => '%B',
                     'D' => '%-d', 'DD' => '%d', 'DDD' => '%-j', 'DDDD' => '%j',
                     'd' => '%w',                'ddd' => '%a',  'dddd' => '%A',
                     'YY' => '%y', 'YYYY' => '%Y',
                     'h' => '%-I', 'hh' => '%I',
                     'H' => '%-H', 'HH' => '%H',
                     'm' => '%-M', 'mm' => '%M',
                     's' => '%-S', 'ss' => '%S',
                     'w' => '%-U', 'ww' => '%U',
                     'W' => '%-V', 'WW' => '%V',
                     'a' => '%P',
                     'A' => '%p',
                     'e' => '%w',
                     'E' => '%u',
                     'X' => '%s' }.freeze

    # @param config_or_value [Hash, Object] configuration hash of a variable out of an {Dashboard} instance
    #  or a value of any kind.
    # @param dashboard [Dashboard] parent dashboard, if applicable; especially needed for query variable
    #  evaluation.
    def initialize(config_or_value, dashboard = nil)
      if config_or_value.is_a? Hash
        @dashboard = dashboard
        @config = config_or_value
        @name = @config['name']
        init_values
      else
        @config = {}
        @raw_value = config_or_value
        @text = config_or_value.to_s
      end
    end

    # Returns the stored value formatted according the given format.
    #
    # Supported formats are: +csv+, +distributed+, +doublequote+, +json+, +percentencode+, +pipe+, +raw+,
    # +regex+, +singlequote+, +sqlstring+, +lucene+, +date+ or +glob+ (default)
    #
    # For details see {https://grafana.com/docs/grafana/latest/variables/advanced-variable-format-options
    # Grafana Advanced variable format options}.
    #
    # For details of +date+ format, see
    # {https://grafana.com/docs/grafana/latest/variables/variable-types/global-variables/#__from-and-__to
    # Grafana global variables $__from and $__to}.
    # Please note that input for +date+ format is unixtime in milliseconds.
    #
    # @param format [String] desired format
    # @return [String] value of stored variable according the specified format
    def value_formatted(format = '')
      value = @raw_value

      # if 'All' is selected for this template variable, capture all values properly
      # (from grafana config or query) and format the results afterwards accordingly
      if value == '$__all'
        if !@config['options'].empty?
          # this query contains predefined values, so capture them and format the values accordingly
          # this happens either for type='custom' or type 'query', if it is never updated
          value = @config['options'].reject { |item| item['value'] == '$__all' }.map { |item| item['value'] }

        elsif @config['type'] == 'query' && !@config['query'].empty?
          # variables in this configuration are not stored in grafana, i.e. if all is selected here,
          # the values have to be fetched from the datasource
          query = ::GrafanaReporter::QueryValueQuery.new(@dashboard)
          query.datasource = @dashboard.grafana.datasource_by_name(@config['datasource'])
          query.variables['result_type'] = Variable.new('object')
          query.raw_query = @config['query']
          result = query.execute

          value = result[:content].map { |item| item[0].to_s }

        else
          # TODO: add support for variable type: 'datasource' and 'adhoc'
        end
      end

      case format
      when 'csv'
        return value.join(',').to_s if multi? && value.is_a?(Array)

        value.to_s

      when 'distributed'
        return value.join(",#{name}=") if multi? && value.is_a?(Array)

        value
      when 'doublequote'
        if multi? && value.is_a?(Array)
          value = value.map { |item| "\"#{item.gsub(/\\/, '\\\\').gsub(/"/, '\\"')}\"" }
          return value.join(',')
        end
        "\"#{value.gsub(/"/, '\\"')}\""

      when 'json'
        if multi? && value.is_a?(Array)
          value = value.map { |item| "\"#{item.gsub(/["\\]/, '\\\\\0')}\"" }
          return "[#{value.join(',')}]"
        end
        "\"#{value.gsub(/"/, '\\"')}\""

      when 'percentencode'
        value = "{#{value.join(',')}}" if multi? && value.is_a?(Array)
        ERB::Util.url_encode(value)

      when 'pipe'
        return value.join('|') if multi? && value.is_a?(Array)

        value

      when 'raw'
        return "{#{value.join(',')}}" if multi? && value.is_a?(Array)

        value

      when 'regex'
        if multi? && value.is_a?(Array)
          value = value.map { |item| item.gsub(%r{[/$.|\\]}, '\\\\\0') }
          return "(#{value.join('|')})"
        end
        value.gsub(%r{[/$.|\\]}, '\\\\\0')

      when 'singlequote'
        if multi? && value.is_a?(Array)
          value = value.map { |item| "'#{item.gsub(/'/, '\\\\\0')}'" }
          return value.join(',')
        end
        "'#{value.gsub(/'/, '\\\\\0')}'"

      when 'sqlstring'
        if multi? && value.is_a?(Array)
          value = value.map { |item| "'#{item.gsub(/'/, "''")}'" }
          return value.join(',')
        end
        "'#{value.gsub(/'/, "''")}'"

      when 'lucene'
        if multi? && value.is_a?(Array)
          value = value.map { |item| "\"#{item.gsub(%r{[" |=/\\]}, '\\\\\0')}\"" }
          return "(#{value.join(' OR ')})"
        end
        value.gsub(%r{[" |=/\\]}, '\\\\\0')

      when /^date(?::(?<format>.*))?$/
        if multi? && value.is_a?(Array)
          raise GrafanaError, "Date format cannot be specified for a variable containing an array of values"
        end
        Variable.format_as_date(value, Regexp.last_match(1))

      when ''
        # default
        if multi? && value.is_a?(Array)
          value = value.map { |item| "'#{item.gsub(/'/, "''")}'" }
          return value.join(',')
        end
        value.gsub(/'/, "''")

      else
        # glob and all unknown
        return "{#{value.join(',')}}" if multi? && value.is_a?(Array)

        value
      end
    end

    # @return [Boolean] true, if the value can contain multiple selections, i.e. can contain an Array or does contain all
    def multi?
      return true if @raw_value == '$__all'
      return @config['multi'] unless @config['multi'].nil?

      @raw_value.is_a? Array
    end

    # @return [Object] raw value of the variable
    def raw_value=(new_val)
      @raw_value = new_val
      @raw_value = @raw_value.to_s unless @raw_value.is_a?(Array)
      new_text = @raw_value
      if @config['options']
        val = @config['options'].select { |item| item['value'] == @raw_value }
        new_text = val.first['text'] unless val.empty?
      end
      @text = new_text
    end

    # Applies the date format according
    # {https://grafana.com/docs/grafana/latest/variables/variable-types/global-variables/#__from-and-__to}
    # and {https://momentjs.com/docs/#/displaying/} to a given value.
    # @param value [String] time as milliseconds to be formatted
    # @param format [String] format string in which the time value shall be returned
    # @return [String] time converted to the specified time format
    def self.format_as_date(value, format)
      return (Float(value) / 1000).to_i.to_s if format == 'seconds'
      return Time.at((Float(value) / 1000).to_i).utc.iso8601(3) if !format || (format == 'iso')

      # build array of known matches
      matches = []
      work_string = format
      until work_string.empty?
        tmp = work_string.scan(/^(?:M{1,4}|D{1,4}|d{1,4}|e|E|w{1,2}|W{1,2}|Y{4}|Y{2}|A|a|H{1,2}|
                                    h{1,2}|k{1,2}|m{1,2}|s{1,2}|S+|X)/x)

        if tmp.empty?
          matches << work_string[0]
          work_string = work_string.sub(/^#{work_string[0]}/, '')
        else
          matches << tmp[0]
          work_string = work_string.sub(/^#{tmp[0]}/, '')
        end
      end

      format_string = ''.dup
      matches.each do |match|
        replacement = DATE_MATCHES[match]
        format_string << (replacement || match)
      end

      Time.at((Float(value) / 1000).to_i).strftime(format_string)
    end

    private

    def init_values
      case @config['type']
      when 'constant'
        self.raw_value = @config['query']

      else
        if !@config['current'].nil?
          self.raw_value = @config['current']['value']
        else
          raise GrafanaError.new("Grafana variable with type '#{@config['type']}' and name '#{@config['name']}' cannot be handled properly by the reporter. Check your results and raise a ticket on github.")
        end
      end
    end
  end
end

# frozen_string_literal: true

module Grafana
  # This class standardizes all webcalls. Key functionality is to properly support HTTPS calls as a base functionality.
  class WebRequest
    attr_accessor :relative_url, :options

    @ssl_cert = nil

    class << self
      attr_accessor :ssl_cert
    end

    # Initializes a specific HTTP request.
    #
    # Default (can be overridden, by specifying the options Hash):
    #   accept: 'application/json'
    #   request: Net::HTTP::Get
    #   content_type: 'application/json'
    #
    # @param base_url [String] URL which shall be queried
    # @param options [Hash] options, which shall be merged to the request. Also allows `+logger+` option
    def initialize(base_url, options = {})
      @base_url = base_url
      default_options = { accept: 'application/json', request: Net::HTTP::Get, content_type: 'application/json' }
      @options = default_options.merge(options.reject { |k, _v| k == :logger && k == :relative_url })
      @relative_url = options[:relative_url]
      @logger = options[:logger] || Logger.new(nil)
    end

    # Executes the HTTP request
    #
    # @param timeout [Integer] number of seconds to wait, before the http request is cancelled, defaults to 60 seconds
    # @return [Response] HTTP response object
    def execute(timeout = nil)
      timeout ||= 60

      uri = URI.parse("#{@base_url}#{@relative_url}")
      @http = Net::HTTP.new(uri.host, uri.port)
      configure_ssl if @base_url =~ /^https/

      @http.read_timeout = timeout.to_i

      request = @options[:request].new(uri.request_uri)
      request['Accept'] = @options[:accept] if @options[:accept]
      request['Content-Type'] = @options[:content_type] if @options[:content_type]
      request['Authorization'] = @options[:authorization] if @options[:authorization]
      request.body = @options[:body]

      @logger.debug("Requesting #{uri} with '#{@options[:body]}' and timeout '#{timeout}'")
      response = @http.request(request)
      @logger.debug("Received response #{response}")
      @logger.debug("HTTP response body: #{response.body}") unless response.code =~ /^2.*/

      response
    end

    private

    def configure_ssl
      @http.use_ssl = true
      @http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      if self.class.ssl_cert && !File.file?(self.class.ssl_cert)
        @logger.warn('SSL certificate file does not exist.')
      elsif self.class.ssl_cert
        @http.cert_store = OpenSSL::X509::Store.new
        @http.cert_store.set_default_paths
        @http.cert_store.add_file(self.class.ssl_cert)
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This module contains special extensions for use in the reporter.
  module Logger
    # This logger enables a special use case, so that one and the same log
    # will automatically be send to two different logger destinations.
    #
    # One destination is the set {#additional_logger=} which respects the
    # configured severity. The other destination is an internal logger, which
    # will always log all messages in mode Logger::Severity::Debug. All messages
    # of the internal logger can easily be retrieved, by using the
    # {#internal_messages} method.
    #
    # Except the {#level=} setting, all calls to the logger will immediately
    # be delegated to the internal logger and the configured {#additional_logger=}.
    # By having this behavior, the class can be used wherever the standard Logger
    # can also be used.
    class TwoWayDelegateLogger
      def initialize
        @internal_messages = StringIO.new
        @internal_logger = ::Logger.new(@internal_messages)
        @internal_logger.level = ::Logger::Severity::DEBUG
        @additional_logger = ::Logger.new(nil)
      end

      # Sets the severity level of the additional logger to the given severity.
      # @param severity one of Logger::Severity
      def level=(severity)
        @additional_logger.level = severity
      end

      # @return [String] all messages of the internal logger.
      def internal_messages
        @internal_messages.string
      end

      # Used to set the additional logger in this class to an already existing
      # logger.
      # @param logger [Logger] sets the additional logger to the given value.
      def additional_logger=(logger)
        @additional_logger = logger || ::Logger.new(nil)
      end

      # Delegates all not configured calls to the internal and the additional logger.
      def method_missing(method, *args)
        @internal_logger.send(method, *args)
        @additional_logger.send(method, *args)
      end

      # Registers all methods to which the internal logger responds.
      def respond_to_missing?(method, *_args)
        super
        @internal_logger.respond_to?(method)
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # The abstract base class, which is to be implemented for different table
  # output formats. By implementing this class, you e.g. can decide if a table
  # will be formatted as CSV, JSON or any other format.
  class AbstractTableFormatStrategy
    @@subclasses = []

    def self.inherited(obj)
      @@subclasses << obj
    end

    # @param abbreviation [String] name of the requested table format strategy
    # @return [AbstractTableFormatStrategy] fitting strategy instance for the given name
    def self.get(abbreviation)
      @@subclasses.select { |item| item.abbreviation == abbreviation }.first.new
    end

    # @abstract
    # @return [String] short name of the current stategy, under which it shall be accessible
    def self.abbreviation
      raise NotImplementedError
    end

    # Used to format a given content array to the desired output format. The default
    # implementation applies the {#format_rules} to create a custom string export. If
    # this is not sufficient for a desired table format, you may simply overwrite this
    # function to have full freedom about the desired output.
    # @param content [Hash] datasource table result
    # @param include_headline [Boolean] true, if headline should be included in result
    # @param transposed [Boolean] true, if result array is in transposed format
    # @return [String] formatted in table format
    def format(content, include_headline, transposed)
      result = content[:content]

      # add the headline at the correct position to the content array
      if include_headline
        if transposed
          result.each_index do |i|
            result[i] = [content[:header][i]] + result[i]
          end
        else
          result = result.unshift(content[:header])
        end
      end

      # translate the content to a table
      result.map do |row|
        format_rules[:row_start] + row.map do |item|
          value = item.to_s
          if format_rules[:replace_string_or_regex]
            value = value.gsub(format_rules[:replace_string_or_regex], format_rules[:replacement])
          end

          format_rules[:cell_start] + value + format_rules[:cell_end]
        end.join(format_rules[:between_cells])
      end.join(format_rules[:row_end])
    end

    # Formatting rules, which are applied to build the table output format.
    def format_rules
      {
        row_start: '',
        row_end: '',
        cell_start: '',
        between_cells: '',
        cell_end: '',
        replace_string_or_regex: nil,
        replacement: ''
      }
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # Implements a default table format strategy, which will return tables
  # as CSV formatted strings.
  class CsvTableFormatStrategy < AbstractTableFormatStrategy
    # @see AbstractTableFormatStrategy#abbreviation
    def self.abbreviation
      'csv'
    end

    # @see AbstractTableFormatStrategy#format_rules
    def format_rules
      {
        row_start: '',
        row_end: "\n",
        cell_start: '',
        between_cells: ', ',
        cell_end: '',
        replace_string_or_regex: ',',
        replacement: '\\,'
      }
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  # @abstract Override {#pre_process} and {#post_process} in subclass.
  #
  # Superclass containing everything for all queries towards grafana.
  class AbstractQuery
    attr_accessor :datasource
    attr_writer :raw_query
    attr_reader :variables, :result, :panel, :dashboard

    def timeout
      return @variables['timeout'].raw_value if @variables['timeout']
      return @variables['grafana_default_timeout'].raw_value if @variables['grafana_default_timeout']

      nil
    end

    # @param grafana_obj [Object] {Grafana::Grafana}, {Grafana::Dashboard} or {Grafana::Panel} object for which the query is executed
    # @param opts [Hash] hash options, which may consist of:
    # @option opts [Hash] :variables hash of variables, which shall be used to replace variable references in the query
    # @option opts [Boolean] :ignore_dashboard_defaults True if {#assign_dashboard_defaults} should not be called
    # @option opts [Boolean] :do_not_use_translated_times True if given from and to times should used as is, without being resolved to reporter times - using this parameter can lead to inconsistent report contents
    def initialize(grafana_obj, opts = {})
      if grafana_obj.is_a?(Grafana::Panel)
        @panel = grafana_obj
        @dashboard = @panel.dashboard
        @grafana = @dashboard.grafana

      elsif grafana_obj.is_a?(Grafana::Dashboard)
        @dashboard = grafana_obj
        @grafana = @dashboard.grafana

      elsif grafana_obj.is_a?(Grafana::Grafana)
        @grafana = grafana_obj

      elsif !grafana_obj
        # nil given

      else
        raise GrafanaReporterError, "Internal error in AbstractQuery: given object is of type #{grafana_obj.class.name}, which is not supported"
      end
      @logger = @grafana ? @grafana.logger : ::Logger.new($stderr, level: :info)
      @variables = {}
      @variables['from'] = Grafana::Variable.new(nil)
      @variables['to'] = Grafana::Variable.new(nil)

      assign_dashboard_defaults unless opts[:ignore_dashboard_defaults]
      opts[:variables].each { |k, v| assign_variable(k, v) } if opts[:variables].is_a?(Hash)

      @translate_times = true
      @translate_times = false if opts[:do_not_use_translated_times]
    end

    # @abstract
    #
    # Runs the whole process to receive values properly from this query:
    # - calls {#pre_process}
    # - executes this query against the {Grafana::AbstractDatasource} implementation instance
    # - calls {#post_process}
    #
    # @return [Hash] result of the query in standardized format
    def execute
      return @result unless @result.nil?

      from = @variables['from'].raw_value
      to = @variables['to'].raw_value
      if @translate_times
        from = translate_date(@variables['from'], @variables['grafana_report_timestamp'], false, @variables['from_timezone'] ||
                              @variables['grafana_default_from_timezone'])
        to = translate_date(@variables['to'], @variables['grafana_report_timestamp'], true, @variables['to_timezone'] ||
                            @variables['grafana_default_to_timezone'])
      end

      pre_process
      raise DatasourceNotSupportedError.new(@datasource, self) if @datasource.is_a?(Grafana::UnsupportedDatasource)

      begin
        @result = @datasource.request(from: from, to: to, raw_query: raw_query, variables: @variables,
                                      prepared_request: @grafana.prepare_request, timeout: timeout,
                                      grafana_version: @grafana.version)
        if @variables['verbose_log']
          @logger.debug("Raw result: #{@result}") if @variables['verbose_log'].raw_value.downcase == "true"
        end
      rescue ::Grafana::GrafanaError
        # grafana errors will be directly passed through
        raise
      rescue GrafanaReporterError
        # grafana errors will be directly passed through
        raise
      rescue StandardError => e
        raise DatasourceRequestInternalError.new(@datasource, "#{e.message}\n#{e.backtrace.join("\n")}")
      end

      raise DatasourceRequestInvalidReturnValueError.new(@datasource, @result) unless datasource_response_valid?

      post_process
      if @variables['verbose_log']
        @logger.debug("Formatted result: #{@result}") if @variables['verbose_log'].raw_value.downcase == "true"
      end
      @result
    end

    # Overwrite this function to extract a proper raw query value from this object.
    #
    # If the property +@raw_query+ is not set manually by the calling object, this
    # method may be overwritten to extract the raw query from this object instead.
    def raw_query
      @raw_query
    end

    # @abstract
    #
    # Overwrite this function to perform all necessary actions, before the query is actually executed.
    # Here you can e.g. set values of variables or similar.
    #
    # Especially for direct queries, it is essential to set the +@datasource+ variable at latest here in the
    # subclass.
    def pre_process
      raise NotImplementedError
    end

    # @abstract
    #
    # Use this function to format the raw result of the @result variable to conform to the expected return value.
    def post_process
      raise NotImplementedError
    end

    # Transposes the given result.
    #
    # NOTE: Only the +:content+ of the given result hash is transposed. The +:header+ is ignored.
    #
    # @param result [Hash] preformatted sql hash, (see {Grafana::AbstractDatasource#request})
    # @param transpose_variable [Grafana::Variable] true, if the result hash shall be transposed
    # @return [Hash] transposed query result
    def transpose(result, transpose_variable)
      return result unless transpose_variable
      return result unless transpose_variable.raw_value == 'true'

      result[:content] = result[:content].transpose

      result
    end

    # Filters columns out of the query result.
    #
    # Multiple columns may be filtered. Therefore the column titles have to be named in the
    # {Grafana::Variable#raw_value} and have to be separated by +,+ (comma).
    #
    # Commas can be used in a format string, but need to be escaped by using +_,+.
    # @param result [Hash] preformatted sql hash, (see {Grafana::AbstractDatasource#request})
    # @param filter_columns_variable [Grafana::Variable] column names, which shall be removed in the query result
    # @return [Hash] filtered query result
    def filter_columns(result, filter_columns_variable)
      return result unless filter_columns_variable

      filter_columns = filter_columns_variable.raw_value
      filter_columns.split(/(?<!_),/).each do |filter_column|
        pos = result[:header].index(filter_column.gsub("_,", ","))

        unless pos.nil?
          result[:header].delete_at(pos)
          result[:content].each { |row| row.delete_at(pos) }
        end
      end

      result
    end

    # Uses the Kernel#format method to format values in the query results.
    #
    # The formatting will be applied separately for every column. Therefore the column formats have to be named
    # in the {Grafana::Variable#raw_value} and have to be separated by +,+ (comma). If no value is specified for
    # a column, no change will happen.
    #
    # It is also possible to format milliseconds as dates by specifying date formats, e.g. +date:iso+. It is
    # possible to use any date format according
    # {https://grafana.com/docs/grafana/latest/variables/variable-types/global-variables/#from-and-to}
    #
    # Commas can be used in a format string, but need to be escaped by using +_,+.
    # @param result [Hash] preformatted sql hash, (see {Grafana::AbstractDatasource#request})
    # @param formats [Grafana::Variable] formats, which shall be applied to the columns in the query result
    # @return [Hash] formatted query result
    def format_columns(result, formats)
      return result unless formats

      formats.text.split(/(?<!_),/).each_index do |i|
        format = formats.text.split(/(?<!_),/)[i].gsub("_,", ",")
        next if format.empty?

        result[:content].map do |row|
          next unless row.length > i

          begin
            if format =~ /^date:/
              row[i] = ::Grafana::Variable.format_as_date(row[i], format.sub(/^date:/, '')) if row[i]
            else
              row[i] = format % row[i] if row[i]
            end
          rescue StandardError => e
            @logger.error(e.message)
            row[i] = e.message
          end
        end
      end
      result
    end

    # Used to replace values in a query result according given configurations.
    #
    # The given variables will be applied to an appropriate column, depending
    # on the naming of the variable. The variable name ending specifies the column,
    # e.g. a variable named +replace_values_2+ will be applied to the second column.
    #
    # The {Grafana::Variable#text} needs to contain the replace specification.
    # Multiple replacements can be specified by separating them with +,+. If a
    # literal comma is needed, it can be escaped with a backslash:  +\\,+.
    #
    # The rule will be separated from the replacement text with a colon +:+.
    # If a literal colon is wanted, it can be escaped with a backslash: +\\:+.
    #
    # Examples:
    # - Basic string replacement
    #    MyTest:ThisValue
    # will replace all occurences of the text 'MyTest' with 'ThisValue'.
    # - Number comparison
    #     <=10:OK
    # will replace all values smaller or equal to 10 with 'OK'.
    # - Regular expression
    #     ^[^ ]\\+ (\d+)$:\1 is the answer
    # will replace all values matching the pattern, e.g. 'answerToAllQuestions 42' to
    # '42 is the answer'. Important to know: the regular expressions always have to start
    # with +^+ and end with +$+, i.e. the expression itself always has to match
    # the whole content in one field.
    # @param result [Hash] preformatted query result (see {Grafana::AbstractDatasource#request}.
    # @param configs [Array<Grafana::Variable>] one variable for replacing values in one column
    # @return [Hash] query result with replaced values
    def replace_values(result, configs)
      return result if configs.empty?

      configs.each do |key, formats|
        cols = key.split('_')[2..-1].map(&:to_i)

        formats.text.split(/(?<!\\),/).each_index do |j|
          format = formats.text.split(/(?<!\\),/)[j]

          arr = format.split(/(?<!\\):/)
          raise MalformedReplaceValuesStatementError, format if arr.length != 2

          k = arr[0]
          v = arr[1]

          # allow keys and values to contain escaped colons or commas
          k = k.gsub(/\\([:,])/, '\1')
          v = v.gsub(/\\([:,])/, '\1')

          result[:content].map do |row|
            (row.length - 1).downto 0 do |i|
              if cols.include?(i + 1) || cols.empty?

                # handle regular expressions
                if k.start_with?('^') && k.end_with?('$')
                  begin
                    row[i] = row[i].to_s.gsub(/#{k}/, v) if row[i].to_s =~ /#{k}/
                  rescue StandardError => e
                    @logger.error(e.message)
                    row[i] = e.message
                  end

                # handle value comparisons
                elsif (match = k.match(/^ *(?<operator>[<>]=?|<>|=) *(?<number>[+-]?\d+(?:\.\d+)?)$/))
                  skip = false
                  begin
                    val = Float(row[i])
                  rescue StandardError
                    # value cannot be converted to number, simply ignore it as the comparison does not fit here
                    skip = true
                  end

                  unless skip
                    begin
                      op = match[:operator].gsub(/^=$/, '==').gsub(/^<>$/, '!=')
                      if val.public_send(op.to_sym, Float(match[:number]))
                        row[i] = if v.include?('\\1')
                                   v.gsub(/\\1/, row[i].to_s)
                                 else
                                   v
                                 end
                      end
                    rescue StandardError => e
                      @logger.error(e.message)
                      row[i] = e.message
                    end
                  end

                # handle as normal comparison
                elsif row[i].to_s == k
                  row[i] = v
                end
              end
            end
          end
        end
      end

      result
    end

    # Used to build a table output in a custom format.
    # @param result [Hash] preformatted sql hash, (see {Grafana::AbstractDatasource#request})
    # @param opts [Hash] options for the formatting:
    # @option opts [Grafana::Variable] :row_divider requested row divider for the result table, only to be used with table_formatter `adoc_deprecated`
    # @option opts [Grafana::Variable] :column_divider requested row divider for the result table, only to be used with table_formatter `adoc_deprecated`
    # @option opts [Grafana::Variable] :include_headline specifies if table should contain headline, defaults to false
    # @option opts [Grafana::Variable] :table_formatter specifies which formatter shall be used, defaults to 'csv'
    # @option opts [Grafana::Variable] :transposed specifies whether the result table is transposed
    # @return [String] table in custom output format
    def format_table_output(result, opts)
      opts = { include_headline: Grafana::Variable.new('false'),
               table_formatter: Grafana::Variable.new('csv'),
               row_divider: Grafana::Variable.new('| '),
               column_divider: Grafana::Variable.new(' | '),
               transpose: Grafana::Variable.new('false') }.merge(opts.delete_if {|_k, v| v.nil? })

      if opts[:table_formatter].raw_value == 'adoc_deprecated'
        @logger.warn("You are using deprecated 'table_formatter' named 'adoc_deprecated', which will be "\
                     "removed in a future version. Start using 'adoc_plain' or register your own "\
                     "implementation of AbstractTableFormatStrategy.")
        return result[:content].map do |row|
          opts[:row_divider].raw_value + row.map do |item|
            item.to_s.gsub('|', '\\|')
          end.join(opts[:column_divider].raw_value)
        end.join("\n")
      end

      AbstractTableFormatStrategy.get(opts[:table_formatter].raw_value).format(result, opts[:include_headline].raw_value.downcase == 'true', opts[:transpose].raw_value.downcase == 'true')
    end

    # Used to translate the relative date strings used by grafana, e.g. +now-5d/w+ to the
    # correct timestamp. Reason is that grafana does this in the frontend, which we have
    # to emulate here for the reporter.
    #
    # Additionally providing this function the +report_time+ assures that all queries
    # rendered within one report will use _exactly_ the same timestamp in those relative
    # times, i.e. there shouldn't appear any time differences, no matter how long the
    # report is running.
    # @param orig_date [String] time string provided by grafana, usually +from+ or +to+.
    # @param report_time [Grafana::Variable] report start time
    # @param is_to_time [Boolean] true, if the time should be calculated for +to+, false if it shall be
    #   calculated for +from+
    # @param timezone [Grafana::Variable] timezone to use, if not system timezone
    # @return [String] translated date as timestamp string
    def translate_date(orig_date, report_time, is_to_time, timezone = nil)
      @logger.warn("#translate_date has been called without 'report_time' - using current time as fallback.") unless report_time
      report_time ||= ::Grafana::Variable.new(Time.now.to_s)
      orig_date = orig_date.raw_value if orig_date.is_a?(Grafana::Variable)

      return (DateTime.parse(report_time.raw_value).to_time.to_i * 1000).to_s unless orig_date
      return orig_date if orig_date =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
      return orig_date if orig_date =~ /^\d+$/

      # check if a relative date is mentioned
      date_spec = orig_date.clone

      date_spec = date_spec.gsub(/^now/, '')
      raise TimeRangeUnknownError, orig_date unless date_spec

      date = DateTime.parse(report_time.raw_value)
      # TODO: PRIO allow from_translated or similar in ADOC template
      date = date.new_offset(timezone.raw_value) if timezone

      until date_spec.empty?
        fit_match = date_spec.match(%r{^/(?<fit>[smhdwMy])})
        if fit_match
          date = fit_date(date, fit_match[:fit], is_to_time)
          date_spec = date_spec.gsub(%r{^/#{fit_match[:fit]}}, '')
        end

        delta_match = date_spec.match(/^(?<op>(?:-|\+))(?<count>\d+)?(?<unit>[smhdwMy])/)
        if delta_match
          date = delta_date(date, "#{delta_match[:op]}#{delta_match[:count] || 1}".to_i, delta_match[:unit])
          date_spec = date_spec.gsub(/^#{delta_match[:op]}#{delta_match[:count]}#{delta_match[:unit]}/, '')
        end

        raise TimeRangeUnknownError, orig_date unless fit_match || delta_match
      end

      # step back one second, if this is the 'to' time
      date = (date.to_time - 1).to_datetime if is_to_time

      (Time.at(date.to_time.to_i).to_i * 1000).to_s
    end

    private

    # Used to specify variables to be used for this query. This method ensures, that only the values of the
    # {Grafana::Variable} stored in the +variables+ Array are overwritten.
    # @param name [String] name of the variable to set
    # @param variable [Grafana::Variable] variable from which the {Grafana::Variable#raw_value} will be assigned to the query variables
    def assign_variable(name, variable)
      variable = Grafana::Variable.new(variable) unless variable.is_a?(Grafana::Variable)

      @variables[name] ||= variable
      @variables[name].raw_value = variable.raw_value
    end

    # Sets default configurations from the given {Grafana::Dashboard} and store them as settings in the
    # {AbstractQuery}.
    #
    # Following data is extracted:
    # - +from+, by {Grafana::Dashboard#from_time}
    # - +to+, by {Grafana::Dashboard#to_time}
    # - and all variables as {Grafana::Variable}, prefixed with +var-+, as grafana also does it
    def assign_dashboard_defaults
      return unless @dashboard

      assign_variable('from', @dashboard.from_time)
      assign_variable('to', @dashboard.to_time)
      @dashboard.variables.each { |item| assign_variable("var-#{item.name}", item) }
    end

    def datasource_response_valid?
      return false if @result.nil?
      return false unless @result.is_a?(Hash)
      return false if @result.empty?
      return false unless @result.key?(:header)
      return false unless @result.key?(:content)
      return false unless @result[:header].is_a?(Array)
      return false unless @result[:content].is_a?(Array)

      true
    end

    def delta_date(date, delta_count, time_letter)
      # substract specified time
      case time_letter
      when 's'
        (date.to_time + (delta_count * 1)).to_datetime
      when 'm'
        (date.to_time + (delta_count * 60)).to_datetime
      when 'h'
        (date.to_time + (delta_count * 60 * 60)).to_datetime
      when 'd'
        date.next_day(delta_count)
      when 'w'
        date.next_day(delta_count * 7)
      when 'M'
        date.next_month(delta_count)
      when 'y'
        date.next_year(delta_count)
      end
    end

    def fit_date(date, fit_letter, is_to_time)
      # fit to specified time frame
      case fit_letter
      when 's'
        date = DateTime.new(date.year, date.month, date.day, date.hour, date.min, date.sec, date.zone)
        date = (date.to_time + 1).to_datetime if is_to_time
      when 'm'
        date = DateTime.new(date.year, date.month, date.day, date.hour, date.min, 0, date.zone)
        date = (date.to_time + 60).to_datetime if is_to_time
      when 'h'
        date = DateTime.new(date.year, date.month, date.day, date.hour, 0, 0, date.zone)
        date = (date.to_time + 60 * 60).to_datetime if is_to_time
      when 'd'
        date = DateTime.new(date.year, date.month, date.day, 0, 0, 0, date.zone)
        date = date.next_day(1) if is_to_time
      when 'w'
        date = DateTime.new(date.year, date.month, date.day, 0, 0, 0, date.zone)
        date = if date.wday.zero?
                 date.prev_day(7)
               else
                 date.prev_day(date.wday - 1)
               end
        date = date.next_day(7) if is_to_time
      when 'M'
        date = DateTime.new(date.year, date.month, 1, 0, 0, 0, date.zone)
        date = date.next_month if is_to_time
      when 'y'
        date = DateTime.new(date.year, 1, 1, 0, 0, 0, date.zone)
        date = date.next_year if is_to_time
      end

      date
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # @abstract Override {#build} and {#progress}.
  #
  # This class is used to build a report on basis of a given configuration and
  # template.
  #
  # Objects of this class are also stored in {Application::Application}, unless
  # the retention time is over.
  class AbstractReport
    # Array of supported event callback symbols
    EVENT_CALLBACKS = %i[all on_before_create on_after_cancel on_after_finish].freeze

    # Class variable for storing event listeners
    @@event_listeners = {}
    @@event_listeners.default = []

    # @return [String] path to the template
    attr_reader :template

    # @return [Time] time, when the report generation started
    attr_reader :start_time

    # @return [Time] time, when the report generation ended
    attr_reader :end_time

    # @return [Logger] logger object used during report generation
    attr_reader :logger

    # @return [Boolean] true, if the report is or shall be cancelled
    attr_reader :cancel

    # @return [Boolen] true, if the report generation is finished (successfull or not)
    attr_reader :done

    # @param config [Configuration] configuration object
    def initialize(config)
      @config = config
      @logger = Logger::TwoWayDelegateLogger.new
      @logger.additional_logger = @config.logger
      @grafana_instances = {}

      init_before_create
    end

    # Registers a new event listener object.
    # @param event [Symbol] one of EVENT_CALLBACKS
    # @param listener [Object] object responding to #callback(event_symbol, object)
    def self.add_event_listener(event, listener)
      @@event_listeners[event] = [] if @@event_listeners[event] == []
      @@event_listeners[event].push(listener)
    end

    # Removes all registeres event listener objects
    def self.clear_event_listeners
      @@event_listeners = {}
      @@event_listeners.default = []
    end

    # @param instance [String] requested grafana instance
    # @return [Grafana::Grafana] the requested grafana instance.
    def grafana(instance)
      unless @grafana_instances[instance]
        @grafana_instances[instance] = ::Grafana::Grafana.new(@config.grafana_host(instance),
                                                              @config.grafana_api_key(instance),
                                                              logger: @logger)
      end
      @grafana_instances[instance]
    end

    # Call to request cancelling the report generation.
    # @return [void]
    def cancel!
      @cancel = true
      logger.info('Cancelling report generation invoked.')
      notify(:on_after_cancel)
    end

    # @return [String] path to the report destination file
    def path
      @destination_file_or_path.respond_to?(:path) ? @destination_file_or_path.path : @destination_file_or_path
    end

    # Deletes the report file object.
    # @return [void]
    def delete_file
      if @destination_file_or_path.is_a?(Tempfile)
        @destination_file_or_path.unlink
      elsif @destination_file_or_path.is_a?(File)
        @destination_file_or_path.delete
      end
      @destination_file_or_path = nil
    end

    # @return [Float] time in seconds, that the report generation took
    def execution_time
      return nil if start_time.nil?
      return end_time - start_time unless end_time.nil?

      Time.now - start_time
    end

    # @return [Array] error messages during report generation.
    def error
      @error || []
    end

    # @return [String] status of the report as string, either 'not started', 'in progress', 'cancelling',
    #   'cancelled', 'died' or 'finished'.
    def status
      return 'not started' unless @start_time
      return 'cancelled' if done && cancel
      return 'cancelling' if !done && cancel
      return 'finished' if done && error.empty?
      return 'died' if done && !error.empty?

      'in progress'
    end

    # @return [String] string containing all messages ([Logger::Severity::DEBUG]) of the logger during report
    #   generation.
    def full_log
      logger.internal_messages
    end

    # Is being called to start the report generation. To execute the specific report generation, this function
    # calls the abstract {#build} method with the given parameters.
    # @param template [String] path to the template to be used, trailing extension may be omitted, whereas {#default_template_extension} will be appended
    # @param destination_file_or_path [String or File] path to the destination report or file object to use
    # @param custom_attributes [Hash] custom attributes, which shall be merged with priority over the configuration
    # @return [void]
    def create_report(template, destination_file_or_path = nil, custom_attributes = {})
      init_before_create
      @template = template
      @destination_file_or_path = destination_file_or_path
      @custom_attributes = custom_attributes

      # automatically add extension, if a file with default template extension exists
      @template = "#{@template}.#{self.class.default_template_extension}" if File.file?("#{@template}.#{self.class.default_template_extension}") && !File.file?(@template.to_s)
      raise MissingTemplateError, "#{@template}.#{self.class.default_template_extension}" unless File.file?(@template.to_s)

      notify(:on_before_create)
      @start_time = Time.new
      logger.info("Report started at #{@start_time}")
      logger.info("You are running ruby-grafana-reporter version #{GRAFANA_REPORTER_VERSION.join('.')}.")
      logger.info("A newer version is released. Check out https://github.com/divinity666/ruby-grafana-reporter/releases/latest") unless @config.latest_version_check_ok?
      build
    rescue MissingTemplateError => e
      @logger.error(e.message)
      @error = [e.message]
      done!
      raise e
    rescue StandardError => e
      # catch all errors during execution
      died_with_error(e)
      raise e
    ensure
      done!
    end

    # @abstract
    # Needs to be overridden by the report implementation.
    def build(template, destination_file_or_path, custom_attributes)
      raise NotImplementedError
    end

    # Used to calculate the progress of a report. By default expects +@total_steps+ to contain the total
    # number of steps, which will be processed with each call of {#next_step}.
    # @return [Integer] number between 0 and 100, representing the current progress of the report creation.
    def progress
      return @current_pos.to_i if @total_steps.to_i.zero?

      @current_pos.to_f / @total_steps
    end

    # Increments the progress.
    # @return [Integer] number of the current progress position.
    def next_step
      @current_pos += 1
      @current_pos
    end

    # @abstract
    # Provided class objects need to implement a method +build_demo_entry(panel)+.
    # @return [Array<Class>] array of class objects, which shall be included in a demo report
    def self.demo_report_classes
      raise NotImplementedError
    end

    # @abstract
    # @return [String] specifying the default extension of a template file
    def self.default_template_extension
      raise NotImplementedError
    end

    # @abstract
    # @return [String] specifying the default extension of a rendered result file
    def self.default_result_extension
      raise NotImplementedError
    end

    private

    # Called, if the report generation has died with an error.
    # @param error [StandardError] occured error
    # @return [void]
    def died_with_error(error)
      @error = [error.message] << [error.backtrace]
      done!
    end

    def init_before_create
      @done = false
      @start_time = nil
      @end_time = nil
      @cancel = false
      @current_pos = 0
    end

    def done!
      return if @done

      @destination_file_or_path.close if @destination_file_or_path.is_a?(File)
      @done = true
      @end_time = Time.new
      @start_time ||= @end_time
      logger.info("Report creation ended after #{@end_time.to_i - @start_time.to_i} seconds with status '#{status}'")
      notify(:on_after_finish)
    end

    def notify(event)
      (@@event_listeners[:all] + @@event_listeners[event]).each do |listener|
        logger.debug("Informing event listener '#{listener.class}' about event '#{event}' for report '#{object_id}'.")
        begin
          res = listener.callback(event, self)
          logger.debug("Event listener '#{listener.class}' for event '#{event}' and report '#{object_id}' returned "\
                       "with result '#{res}'.")
        rescue StandardError => e
          msg = "Event listener '#{listener.class}' for event '#{event}' and report '#{object_id}' returned with "\
                "error: #{e.message} - #{e.backtrace}."
          puts msg
          logger.error(msg)
        end
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class is used to query alerts from grafana.
  class AlertsTableQuery < AbstractQuery
    # Check if mandatory {Grafana::Variable} +columns+ is specified in variables.
    #
    # The value of the +columns+ variable has to be a comma separated list of column titles, which
    # need to be included in the following list:
    # - limit
    # - dashboardId
    # - panelId
    # - query
    # - state
    # - folderId
    # - dashboardQuery
    # - dashboardTag
    # @return [void]
    def pre_process
      raise MissingMandatoryAttributeError, 'columns' unless @raw_query['columns']

      @datasource = Grafana::GrafanaAlertsDatasource.new(nil)
    end

    # Filter the query result for the given columns and sets the result in the preformatted SQL
    # result stlye.
    #
    # Additionally it applies {AbstractQuery#format_columns}, {AbstractQuery#replace_values} and
    # {AbstractQuery#filter_columns}.
    # @return [void]
    def post_process
      @result = format_columns(@result, @variables['format'])
      @result = replace_values(@result, @variables.select { |k, _v| k =~ /^replace_values_\d+/ })
      @result = filter_columns(@result, @variables['filter_columns'])

      @result = format_table_output(@result,
                                    row_divider: @variables['row_divider'],
                                    column_divider: @variables['column_divider'],
                                    table_formatter: @variables['table_formatter'],
                                    include_headline: @variables['include_headline'],
                                    transpose: @variables['transpose'])
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class is used to query annotations from grafana.
  class AnnotationsTableQuery < AbstractQuery
    # Check if mandatory {Grafana::Variable} +columns+ is specified in variables.
    #
    # The value of the +columns+ variable has to be a comma separated list of column titles, which
    # need to be included in the following list:
    # - limit
    # - alertId
    # - userId
    # - type
    # - tags
    # - dashboardId
    # - panelId
    # @return [void]
    def pre_process
      raise MissingMandatoryAttributeError, 'columns' unless @raw_query['columns']

      @datasource = Grafana::GrafanaAnnotationsDatasource.new(nil)
    end

    # Filters the query result for the given columns and sets the result
    # in the preformatted SQL result style.
    #
    # Additionally it applies {AbstractQuery#format_columns}, {AbstractQuery#replace_values} and
    # {AbstractQuery#filter_columns}.
    # @return [void]
    def post_process
      @result = format_columns(@result, @variables['format'])
      @result = replace_values(@result, @variables.select { |k, _v| k =~ /^replace_values_\d+/ })
      @result = filter_columns(@result, @variables['filter_columns'])

      @result = format_table_output(@result,
                                    row_divider: @variables['row_divider'],
                                    column_divider: @variables['column_divider'],
                                    table_formatter: @variables['table_formatter'],
                                    include_headline: @variables['include_headline'],
                                    transpose: @variables['transpose'])
    end
  end
end

# frozen_string_literal: true

# In this namespace all objects needed for the grafana reporter are collected.
module GrafanaReporter
  # Used to store the whole settings, which are necessary to run the reporter.
  # It can read configuration files, but might also be configured programmatically.
  #
  # This class also contains a function {#validate}, which ensures that the
  # provided settings are set properly.
  #
  # Using this class is embedded in the {Application::Application#configure_and_run}.
  #
  class Configuration
    # @return [AbstractReport] specific report class, which should be used.
    attr_accessor :report_class
    attr_accessor :logger

    # Default file name for grafana reporter configuration file
    DEFAULT_CONFIG_FILE_NAME = 'grafana_reporter.config'

    # Returned by {#mode} if only a connection test shall be executed.
    MODE_CONNECTION_TEST = 'test'
    # Returned by {#mode} if only one configured report shall be rendered.
    MODE_SINGLE_RENDER = 'single-render'
    # Returned by {#mode} if the default webservice shall be started.
    MODE_SERVICE = 'webservice'

    # Used to access the configuration hash. To make sure, that the configuration is
    # valid, call {#validate}.
    attr_reader :config

    def initialize
      @config = {}
      @logger = ::Logger.new($stderr, level: :info)
    end

    # Reads a given configuration file.
    # @param config_file [String] path to configuration file, defaults to DEFAULT_CONFIG_FILE_NAME
    # @return [Hash] configuration hash to be set as {Configuration#config}
    def load_config_from_file(config_file = nil)
      config_file ||= DEFAULT_CONFIG_FILE_NAME
      self.config = YAML.load_file(config_file)
    rescue StandardError => e
      raise ConfigurationError, "Could not read config file '#{config_file}' (Error: #{e.message})"
    end

    # Used to overwrite the current configuration.
    def config=(new_config)
      @config = new_config
      update_configuration
    end

    # @return [String] mode, in which the reporting shall be executed. One of {MODE_CONNECTION_TEST},
    #   {MODE_SINGLE_RENDER} and {MODE_SERVICE}.
    def mode
      if (get_config('grafana-reporter:run-mode') != MODE_CONNECTION_TEST) &&
         (get_config('grafana-reporter:run-mode') != MODE_SINGLE_RENDER)
        return MODE_SERVICE
      end

      get_config('grafana-reporter:run-mode')
    end

    # @return [String] full path of configured report template. Only needed in {MODE_SINGLE_RENDER}.
    def template
      return nil if get_config('default-document-attributes:var-template').nil?

      "#{templates_folder}#{get_config('default-document-attributes:var-template')}"
    end

    # @return [String] destination filename for the report in {MODE_SINGLE_RENDER}.
    def to_file
      return get_config('to_file') || true if mode == MODE_SINGLE_RENDER

      get_config('to_file')
    end

    # @return [Array<String>] names of the configured grafana_instances.
    def grafana_instances
      instances = get_config('grafana')
      instances.keys
    end

    # @param instance [String] grafana instance name, for which the value shall be retrieved.
    # @return [String] configured 'host' for the requested grafana instance.
    def grafana_host(instance = 'default')
      host = get_config("grafana:#{instance}:host")
      raise GrafanaInstanceWithoutHostError, instance if host.nil?

      host
    end

    # @param instance [String] grafana instance name, for which the value shall be retrieved.
    # @return [String] configured 'api_key' for the requested grafana instance.
    def grafana_api_key(instance = 'default')
      get_config("grafana:#{instance}:api_key")
    end

    # @return [String] configured folder, in which the report templates are stored including trailing slash.
    #   By default: current folder.
    def templates_folder
      result = get_config('grafana-reporter:templates-folder') || '.'
      return result.sub(%r{/*$}, '/') unless result.empty?

      result
    end

    # Returns configured folder, in which temporary images during report generation
    # shall be stored including trailing slash. Folder has to be a subfolder of
    # {#templates_folder}. By default: current folder.
    # @return [String] configured folder, in which temporary images shall be stored.
    def images_folder
      img_path = templates_folder
      img_path = if img_path.empty?
                   get_config('default-document-attributes:imagesdir').to_s
                 else
                   img_path + get_config('default-document-attributes:imagesdir').to_s
                 end
      img_path.empty? ? './' : img_path.sub(%r{/*$}, '/')
    end

    # @return [String] name of grafana instance, against which a test shall be executed
    def test_instance
      get_config('grafana-reporter:test-instance')
    end

    # @return [String] configured folder, in which the reports shall be stored including trailing slash.
    #   By default: current folder.
    def reports_folder
      result = get_config('grafana-reporter:reports-folder') || '.'
      return result.sub(%r{/*$}, '/') unless result.empty?

      result
    end

    # @return [Integer] how many hours a generated report shall be retained, before it shall be deleted.
    #   By default: 24.
    def report_retention
      get_config('grafana-reporter:report-retention') || 24
    end

    # @return [Integer] port, on which the webserver shall run. By default: 8815.
    def webserver_port
      get_config('grafana-reporter:webservice-port') || 8815
    end

    # The configuration made with the setting 'default-document-attributes' will
    # be passed 1:1 to the asciidoctor report service. It can be used to preconfigure
    # whatever is essential for the needed report renderings.
    # @return [Hash] configured document attributes
    def default_document_attributes
      get_config('default-document-attributes') || {}
    end

    # Checks if this is the latest ruby-grafana-reporter version. If and how often the check if
    # performed, depends on the configuration setting `check-for-updates`. By default this is
    # 0 (=disabled). If a number >0 is specified, the checks are performed once every n-days on
    # report creation or call of overview webpage.
    # @return [Boolean] true, if is ok, false if a newer version exists
    def latest_version_check_ok?
      return false if @newer_version_exists

      value = get_config('grafana-reporter:check-for-updates') || 0
      return true if value <= 0

      # repeat check only every n-th day
      if @last_version_check
        return true if (Time.now - @last_version_check) < (value * 24*60*60)
      end

      # check for newer version
      @last_version_check = Time.now
      url = 'https://github.com/divinity666/ruby-grafana-reporter/releases/latest'
      response = Grafana::WebRequest.new(url).execute
      return true if response['location'] =~ /.*[\/v]#{GRAFANA_REPORTER_VERSION.join('.')}$/

      @newer_version_exists = true
      return false
    end

    # This function shall be called, before the configuration object is used in the
    # {Application::Application#run}. It ensures, that everything is setup properly
    # and all necessary folders exist. Appropriate errors are raised in case of errors.
    # @param explicit [Boolean] true, if validation shall expect explicit (wizard) configuration file
    # @return [void]
    def validate(explicit = false)
      check_deprecation
      validate_schema(schema(explicit), @config)

      # check if set folders exist
      raise FolderDoesNotExistError.new(reports_folder, 'reports-folder') unless File.directory?(reports_folder)
      raise FolderDoesNotExistError.new(templates_folder, 'templates-folder') unless File.directory?(templates_folder)
      raise FolderDoesNotExistError.new(images_folder, 'images-folder') unless File.directory?(images_folder)
    end

    # Can be used to configure or overwrite single parameters.
    #
    # @param path [String] path of the paramter to set, e.g. +grafana-reporter:webservice-port+
    # @param value [Object] value to set
    def set_param(path, value)
      return if path.nil?

      levels = path.split(':')
      last_level = levels.pop

      cur_pos = @config
      levels.each do |subpath|
        cur_pos[subpath] = {} unless cur_pos[subpath]
        cur_pos = cur_pos[subpath]
      end

      cur_pos[last_level] = value
      update_configuration
    end

    # Merge the given configuration object settings with the current config, i.e. overwrite and add all
    # settings from the given config, but keep the not specified configs from the current object.
    #
    # param other_config [Configuration] other configuration object
    def merge!(other_config)
      config.merge!(other_config.config) { |_key, v1, v2| v1.is_a?(Hash) && v2.is_a?(Hash) ? v1.merge(v2) : v2 }
      update_configuration
    end

    private

    def check_deprecation
      return if report_class

      logger.warn('DEPRECATION WARNING: Your configuration explicitly needs to specify the '\
                  '\'grafana-reporter:report-class\' value.  Currently this defaults to '\
                  '\'GrafanaReporter::Asciidoctor::Report\'. You can get rid of this warning, if you '\
                  'explicitly set this configuration in your configuration file. Setting this default will be '\
                  'removed in a future version.')
      set_param('grafana-reporter:report-class', 'GrafanaReporter::Asciidoctor::Report')
    end

    def update_configuration
      debug_level = get_config('grafana-reporter:debug-level')
      rep_class = get_config('grafana-reporter:report-class')

      @logger.level = Object.const_get("::Logger::Severity::#{debug_level}") if debug_level =~ /DEBUG|INFO|WARN|
                                                                                                ERROR|FATAL|UNKNOWN/x
      self.report_class = Object.const_get(rep_class) if rep_class
      ::Grafana::WebRequest.ssl_cert = get_config('grafana-reporter:ssl-cert')

      # register callbacks
      callbacks = get_config('grafana-reporter:callbacks')
      return unless callbacks

      callbacks.each do |url, event|
        AbstractReport.add_event_listener(event.to_sym, ReportWebhook.new(url))
      end
    end

    def get_config(path)
      return if path.nil?

      cur_pos = @config
      path.split(':').each do |subpath|
        cur_pos = cur_pos[subpath] if cur_pos
      end
      cur_pos
    end

    def validate_schema(schema, subject, pattern = nil)
      return nil if subject.nil?

      schema.each do |key, config|
        type, min_occurence, pattern, next_level = config

        validate_schema(next_level, subject[key], pattern) if next_level

        if key.nil?
          # apply to all on this level
          raise ConfigurationError, "Unhandled configuration data type '#{subject.class}'." unless subject.is_a?(Hash)

          if subject.length < min_occurence
            raise ConfigurationDoesNotMatchSchemaError.new(key, 'occur', min_occurence, subject.length)
          end

          subject.each do |k, _v|
            sub_scheme = {}
            sub_scheme[k] = schema[nil]
            validate_schema(sub_scheme, subject)
          end

        # apply to single item
        elsif subject.is_a?(Hash)
          if !subject.key?(key) && min_occurence.positive?
            raise ConfigurationDoesNotMatchSchemaError.new(key, 'occur', min_occurence, 0)
          elsif !subject[key].is_a?(type) && subject.key?(key)
            raise ConfigurationDoesNotMatchSchemaError.new(key, 'be a', type, subject[key].class)
          elsif pattern
            # validate for regex
            unless subject[key].to_s =~ pattern
              raise ConfigurationDoesNotMatchSchemaError.new(key, 'match pattern', pattern.inspect, subject[key].to_s)
            end
          end

        else
          raise ConfigurationError, "Unhandled configuration data type '#{subject.class}'."
        end
      end

      # validate also if subject has further configurations, which are not known by the reporter
      subject.each do |item, _subitems|
        schema_config = schema[item] || schema[nil]
        if schema_config.nil?
          logger.warn("Item '#{item}' in configuration is unknown to the reporter and will be ignored")
        end
      end
    end

    def schema(explicit)
      {
        'grafana' =>
         [
           Hash, 1, nil,
           {
             nil =>
              [
                Hash, 1, nil,
                {
                  'host' => [String, 1, %r{^http(s)?://.+}],
                  'api_key' => [String, 0, %r{^(?:[\w]+[=]*)?$}]
                }
              ]
           }
         ],
        'default-document-attributes' => [Hash, explicit ? 1 : 0, nil],
        'to_file' => [String, 0, nil],
        'grafana-reporter' =>
        [
          Hash, 1, nil,
          {
            'check-for-updates' => [Integer, 0, /^[0-9]*$/],
            'debug-level' => [String, 0, /^(?:DEBUG|INFO|WARN|ERROR|FATAL|UNKNOWN)?$/],
            'run-mode' => [String, 0, /^(?:test|single-render|webservice)?$/],
            'test-instance' => [String, 0, nil],
            'templates-folder' => [String, explicit ? 1 : 0, nil],
            'report-class' => [String, 1, nil],
            'reports-folder' => [String, explicit ? 1 : 0, nil],
            'report-retention' => [Integer, explicit ? 1 : 0, nil],
            'ssl-cert' => [String, 0, nil],
            'webservice-port' => [Integer, explicit ? 1 : 0, nil],
            'callbacks' => [Hash, 0, nil, { nil => [String, 1, nil] }]
          }
        ]
      }
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class provides a console configuration wizard, to reduce the manual efforts that have
  # to be spent for that action and to reduce mistakes as good as possible.
  class ConsoleConfigurationWizard
    # Provides a command line configuration wizard for setting up the necessary configuration
    # file.
    def start_wizard(config_file, console_config)
      action = overwrite_or_use_config_file(config_file)
      return if action == 'abort'

      config = create_config_wizard(config_file, console_config) if action == 'overwrite'
      config ||= Configuration.new

      begin
        config.config = YAML.load_file(config_file)
      rescue StandardError => e
        raise ConfigurationError, "Could not read config file '#{config_file}' (Error: #{e.message})\n"\
              "Source:\n#{File.read(config_file)}"
      end

      begin
        config.validate(true)
        puts 'Configuration file validated successfully.'
      rescue ConfigurationError => e
        raise e
      end

      demo_report = create_demo_report(config)

      demo_report ||= '<<your_report_name>>'
      config_param = config_file == Configuration::DEFAULT_CONFIG_FILE_NAME ? '' : " -c #{config_file}"
      program_call = "#{Gem.ruby} #{$PROGRAM_NAME}"
      program_call = ENV['OCRAN_EXECUTABLE'].gsub("#{Dir.pwd}/".gsub('/', '\\'), '') if ENV['OCRAN_EXECUTABLE']

      puts
      puts 'Now everything is setup properly. Create your reports as required in the templates '\
           'folder and run the reporter either standalone with e.g. the following command:'
      puts
      puts "   #{program_call}#{config_param} -t #{demo_report} -o demo_report.#{config.report_class.default_result_extension}"
      puts
      puts 'or run it as a service using the following command:'
      puts
      puts "   #{program_call}#{config_param}"
      puts
      puts "Open 'http://localhost:#{config.webserver_port}/render?var-template=#{demo_report}' in a webbrowser to"\
           ' test your configuration.'
    end

    private

    def create_config_wizard(config_file, console_config)
      config = Configuration.new

      puts 'This wizard will guide you through an initial configuration for'\
           ' the ruby-grafana-reporter. The configuration file will be created'\
           ' in the current folder. Please make sure to specify necessary paths'\
           ' either with a relative or an absolute path properly.'
      puts
      puts "Wizard is creating configuration file '#{config_file}'."
      puts
      port = ui_config_port
      grafana = ui_config_grafana(console_config)
      templates = ui_config_templates_folder
      reports = ui_config_reports_folder
      images = ui_config_images_folder(templates)
      retention = ui_config_retention

      config_yaml = %(# This configuration has been built with the configuration wizard.

#{grafana}

grafana-reporter:
# Specifies how often the reporter shall check for newer versions [number of days].
# You may set check-for-updates to 0 to disable
  check-for-updates: 1
  report-class: GrafanaReporter::Asciidoctor::Report
  templates-folder: #{templates}
  reports-folder: #{reports}
  report-retention: #{retention}
  webservice-port: #{port}
# you may want to configure the following webhook callbacks to get informed on certain events
#  callbacks:
#    all:
#      - <<your_callback_url>>
#      - ...
#    on_before_create:
#      - <<your_callback_url>>
#      - ...
#    on_after_cancel:
#      - <<your_callback_url>>
#      - ...
#    on_after_finish:
#      - <<your_callback_url>>
#      - ...

default-document-attributes:
  imagesdir: #{images}
# feel free to add here additional asciidoctor document attributes which are applied to all your templates
)

      begin
        File.write(config_file, config_yaml, mode: 'w')
        puts 'Configuration file successfully created.'
      rescue StandardError => e
        raise e
      end

      config
    end

    def create_demo_report(config)
      unless Dir.exist?(config.templates_folder)
        puts "Skip creation of DEMO template, as folder '#{config.templates_folder}' does not exist."
        return nil
      end

      create = user_input('Shall I create a demo report for your new configuration file? Please note '\
                          'that this report might contain confidential information, depending on the '\
                          'confidentiality of the information stored in your dashboard.', 'yN')
      return nil unless create =~ /^(?:y|Y)$/

      demo_report = 'demo_report'
      demo_report_file = "#{config.templates_folder}#{demo_report}.#{config.report_class.default_template_extension}"

      # ask to overwrite file
      if File.exist?(demo_report_file)
        input = user_input("Demo template '#{demo_report_file}' does already exist. Do you want to "\
                           'overwrite it?', 'yN')

        case input
        when /^(?:y|Y)$/
          puts 'Overwriting existing DEMO template.'

        else
          puts 'Skip creation of DEMO template.'
          return demo_report
        end
      end

      grafana = ::Grafana::Grafana.new(config.grafana_host, config.grafana_api_key)
      demo_report_content = DemoReportWizard.new(config.report_class.demo_report_classes).build(grafana)

      begin
        File.write(demo_report_file, demo_report_content, mode: 'w')
        puts "DEMO template '#{demo_report_file}' successfully created."
      rescue StandardError => e
        puts e.message
        return nil
      end

      demo_report
    end

    def ui_config_grafana(config)
      valid = false
      url = nil
      api_key = nil
      until valid
        url ||= user_input('Specify grafana host', 'http://localhost:3000')
        print "Testing connection to '#{url}' #{api_key ? '_with_' : '_without_'} API key..."
        begin
          res = Grafana::Grafana.new(url,
                                     api_key,
                                     logger: config.logger).test_connection
        rescue StandardError => e
          puts
          puts e.message
        end
        puts 'done.'

        case res
        when 'Admin'
          tmp = user_input('Access to grafana is permitted as Admin, which is a potential security risk.'\
                ' Do you want to use another [a]pi key, [r]e-enter url key or [i]gnore?', 'aRi')

          case tmp
          when /(?:i|I)$/
            valid = true

          when /(?:a|A)$/
            print 'Enter API key: '
            api_key = gets.strip

          else
            url = nil
            api_key = nil

          end

        when 'NON-Admin'
          print 'Access to grafana is permitted as NON-Admin.'
          valid = true

        else
          tmp = user_input("Grafana could not be accessed at '#{url}'. Do you want to use an [a]pi key,"\
                ' [r]e-enter url, or [i]gnore and proceed?', 'aRi')

          case tmp
          when /(?:i|I)$/
            valid = true

          when /(?:a|A)$/
            print 'Enter API key: '
            api_key = gets.strip

          else
            url = nil
            api_key = nil

          end

        end
      end
      %(grafana:
  default:
    host: #{url}#{api_key ? "\n    api_key: #{api_key}" : ''}
)
    end

    def ui_config_port
      input = nil
      until input
        input = user_input('Specify port on which reporter shall run', '8815')
        input = nil unless input =~ /[0-9]+/
      end
      input
    end

    def ui_config_templates_folder
      input = nil
      until input
        input = user_input('Specify path where templates shall be stored', './templates')
        input = nil unless validate_config_folder(input)
      end
      input
    end

    def ui_config_reports_folder
      input = nil
      until input
        input = user_input('Specify path where created reports shall be stored', './reports')
        input = nil unless validate_config_folder(input)
      end
      input
    end

    def ui_config_images_folder(parent)
      input = nil
      until input
        input = user_input('Specify path where rendered images shall be stored (relative to templates folder)',
                           './images')
        input = nil unless validate_config_folder(File.join(parent, input))
      end
      input
    end

    def ui_config_retention
      input = nil
      until input
        input = user_input('Specify report retention duration in hours', '24')
        input = nil unless input =~ /[0-9]+/
      end
      input
    end

    def user_input(text, default)
      print "#{text} [#{default}]: "
      input = gets.gsub(/\n$/, '')
      input = default if input.empty?
      input
    end

    def validate_config_folder(folder)
      return true if Dir.exist?(folder)

      print "Directory '#{folder} does not exist: [c]reate, [r]e-enter path or [i]gnore? [cRi]: "
      case gets
      when /^(?:c|C)$/
        begin
          Dir.mkdir(folder)
          puts "Directory '#{folder}' successfully created."
          return true
        rescue StandardError => e
          puts "WARN: Directory '#{folder}' could not be created. Please create it manually."
          puts e.message
        end

      when /^(?:i|I)$/
        puts "WARN: Directory '#{folder}' does not exist. Please create manually."
        return true
      end

      false
    end

    def overwrite_or_use_config_file(config_file)
      return 'overwrite' unless File.exist?(config_file)

      input = nil
      until input
        input = user_input("Configuration file '#{config_file}' already exists. Do you want to [o]verwrite it, "\
                           'use it to for [d]emo report creation only, or [a]bort?', 'odA')
      end

      return 'demo_report' if input =~ /^(?:d|D)$/
      return 'abort' if input =~ /^(?:A|a|odA)$/

      'overwrite'
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class is used to build a demo report based on a real grafana instance. Therefore
  # it checks available grafana dashboards and panels and returns a final template file as
  # string, which can then be used as a template.
  class DemoReportWizard
    # @param query_classes [Array] class objects, for which a demo report shall be created
    def initialize(query_classes)
      @query_classes = query_classes
    end

    # Invokes the build process for the given +grafana+ object. Progress is printed to
    # STDOUT.
    # @param grafana [Grafana] grafana instance, for which the demo report shall be built
    # @return [String] demo template as string
    def build(grafana)
      results = {}

      grafana.dashboard_ids.sample(15).each do |dashboard_id|
        print "Evaluating dashboard '#{dashboard_id}' for building a demo report..."
        dashboard = grafana.dashboard(dashboard_id)

        results = evaluate_dashboard(dashboard, @query_classes - results.keys).merge(results)

        puts "done - #{(@query_classes - results.keys).length} examples to go"
        break if (@query_classes - results.keys).empty?
      end

      if grafana.dashboard_ids.length > 15 && !(@query_classes - results.keys).empty?
        puts 'Aborting evaluating further dashboards after 15 samples.'
      end

      unless (@query_classes - results.keys).empty?
        puts "For #{(@query_classes - results.keys).length} reporter functionalities no appropriate "\
             'examples could be found in the configured grafana instance.'
      end

      format_results(default_result(@query_classes - results.keys).merge(results))
    end

    private

    def default_result(query_classes)
      results = {}

      query_classes.each do |query_class|
        results[query_class] = "No example found for #{query_class.name} in the dashboards."
      end

      results
    end

    def evaluate_dashboard(dashboard, query_classes)
      results = {}

      dashboard.panels.shuffle.each do |panel|
        query_classes.each do |query_class|
          unless query_class.public_instance_methods.include?(:build_demo_entry)
            results[query_class] = "Method 'build_demo_entry' not implemented for #{query_class.name}"
            next
          end

          begin
            result = query_class.new.build_demo_entry(panel)
            results[query_class] = result if result
          rescue Grafana::DatasourceDoesNotExistError
            # properly catch DatasourceDoesNotExist errors here, as they don't lead to a real issue
            # during demo report creation
            # This may e.g. happen if a panel asks e.g. for datasource '-- Dashboard --' which is
            # currently not allowed
          rescue StandardError => e
            puts "#{e.message}\n#{e.backtrace.join("\n")}"
          rescue NotImplementedError
            # Ignore these errors, as it only means, that a class does not implement
            # the demo entry
          end
        end
      end

      results
    end

    def format_results(raw_results)
      results = ['= Demo report',
                 "Created by `+ruby-grafana-reporter+` version #{GRAFANA_REPORTER_VERSION.join('.')}",
                 '== Examples']

      raw_results.each do |k, v|
        results += if v =~ /^[A-Z]/
                     ["=== #{k.to_s.gsub(/.*::/, '')}", v.to_s]
                   else
                     ["=== #{k.to_s.gsub(/.*::/, '')}", 'Sample call:', " #{v.gsub(/\n/, "\n ")}",
                      'Result:', v.to_s]
                   end
      end

      results.join("\n\n")
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # General error of the reporter. All other errors will inherit from this class.
  class GrafanaReporterError < StandardError
    def initialize(message)
      super("GrafanaReporterError: #{message}")
    end
  end

  # Raised if a datasource shall be queried, which is not (yet) supported by the reporter
  class DatasourceNotSupportedError < GrafanaReporterError
    def initialize(datasource, query)
      super("The datasource '#{datasource.name}' is of type '#{datasource.type}' which is currently "\
            "not supported for the query type '#{query}'.")
    end
  end

  # Raised if some unhandled exception is raised during a datasource request execution.
  class DatasourceRequestInternalError < GrafanaReporterError
    def initialize(datasource, message)
      super("The datasource request to '#{datasource.name}' (#{datasource.class}) failed with "\
            "an internal error: #{message}")
    end
  end

  # Raised if the return value of a datasource request does not match the expected return hash.
  class DatasourceRequestInvalidReturnValueError < GrafanaReporterError
    def initialize(datasource, message)
      super("The datasource request to '#{datasource.name}' (#{datasource.class}) "\
            "returned an invalid value: '#{message}'")
    end
  end

  # Thrown, if the requested grafana instance does not have the mandatory 'host'
  # setting configured.
  class GrafanaInstanceWithoutHostError < GrafanaReporterError
    def initialize(instance)
      super("Grafana instance '#{instance}' has been configured without mandatory 'host' setting.")
    end
  end

  # General configuration error. All configuration errors inherit from this class.
  class ConfigurationError < GrafanaReporterError
    def initialize(message)
      super("Configuration error: #{message}")
    end
  end

  # Thrown if a non existing template has been specified.
  class MissingTemplateError < ConfigurationError
    def initialize(template)
      super("Accessing report template file '#{template}' is not possible. Check if file exists and is accessible.")
    end
  end

  # Thrown, if a configured path does not exist.
  class FolderDoesNotExistError < ConfigurationError
    def initialize(folder, config_item)
      super("#{config_item} '#{folder}' does not exist.")
    end
  end

  # Thrown if the configuration does not match the expected schema.
  # Details about how to fix that are provided in the message.
  class ConfigurationDoesNotMatchSchemaError < ConfigurationError
    def initialize(item, verb, expected, currently)
      super("Configuration file does not match schema definition. Expected '#{item}' to #{verb} '#{expected}', "\
            "but was '#{currently}'.")
    end
  end

  # Thrown, if the value configuration in {AbstractQuery#replace_values} is
  # invalid.
  class MalformedReplaceValuesStatementError < GrafanaReporterError
    def initialize(statement)
      super("The specified replace_values statement '#{statement}' is invalid. Make sure it contains"\
            " exactly one not escaped ':' symbol.")
    end
  end

  # Thrown, if a configured parameter is malformed.
  class MalformedAttributeContentError < GrafanaReporterError
    def initialize(message, attribute, content)
      super("The content '#{content}' in attribute '#{attribute}' is malformed: #{message}")
    end
  end

  # Thrown, if a configured time range is not supported by the reporter.
  #
  # If this happens, most likely the reporter has to implement the new
  # time range definition.
  class TimeRangeUnknownError < GrafanaReporterError
    def initialize(time_range)
      super("The specified time range '#{time_range}' is unknown.")
    end
  end

  # Thrown, if a mandatory attribute is not set.
  class MissingMandatoryAttributeError < GrafanaReporterError
    def initialize(attribute)
      super("Missing mandatory attribute '#{attribute}'.")
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class is used to create an image out of a {Grafana::Panel}.
  class PanelImageQuery < AbstractQuery
    # Sets the proper render variables.
    def pre_process
      # TODO: properly show error, if a (maybe a repeated template) panel can not be rendered
      # TODO: ensure that in case of timezones are specified, that they are also forwarded to the image renderer
      # rename "render-" variables
      @variables = @variables.each_with_object({}) { |(k, v), h| h[k.gsub(/^render-/, '')] = v }
      @datasource = Grafana::ImageRenderingDatasource.new(nil)
    end

    # Returns the body of the http query, which contains the raw image.
    def post_process
      @result = @result[:content].first
    end

    # @see AbstractQuery#raw_query
    def raw_query
      { panel: @panel }
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class is used to query properties from a {Grafana::Panel}, such as +description+,
  # +title+ etc.
  class PanelPropertyQuery < AbstractQuery
    # @see Grafana::AbstractQuery#pre_process
    def pre_process
      @datasource = Grafana::GrafanaPropertyDatasource.new(nil)
    end

    # @see Grafana::AbstractQuery#post_process
    def post_process
      @result = @result[:content].first
    end

    # @see Grafana::AbstractQuery#raw_query
    def raw_query
      @raw_query.merge({ panel: @panel })
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class provides a general query implementation for any kind of single value and table queries.
  class QueryValueQuery < AbstractQuery
    # @see Grafana::AbstractQuery#pre_process
    def pre_process
      if @panel
        @panel.resolve_variable_datasource(@variables)
        @datasource = @panel.datasource
      end

      @variables['result_type'] ||= Variable.new('')
    end

    # Executes {AbstractQuery#format_columns}, {AbstractQuery#replace_values} and
    # {AbstractQuery#filter_columns} on the query results.
    #
    # Finally the results are formatted as a asciidoctor table.
    # @see Grafana::AbstractQuery#post_process
    def post_process
      modify_results

      case @variables['result_type'].raw_value
      when 'object'

      when /(?:panel_table|sql_table)/
        @result = format_table_output(@result, row_divider: @variables['row_divider'],
                                               column_divider: @variables['column_divider'],
                                               table_formatter: @variables['table_formatter'],
                                               include_headline: @variables['include_headline'],
                                               transpose: @variables['transpose'])

      when /(?:panel_value|sql_value)/
        tmp = @result[:content] || []
        @result = tmp.flatten.first

      else
        raise StandardError, "Unsupported 'result_type' received: '#{@variables['result_type'].raw_value}'"

      end
    end

    # @see Grafana::AbstractQuery#raw_query
    def raw_query
      return @raw_query if @raw_query

      case @variables['result_type'].raw_value
      when /(?:panel_table|panel_value)/
        @variables['query'] ? @panel.query(@variables['query'].raw_value) : @panel.query(nil)

      when /(?:sql_table|sql_value)/
        nil

      else
        raise StandardError, "Unsupported 'result_type' received: '#{@variables['result_type'].raw_value}'"

      end
    end

    private

    def modify_results
      @result = format_columns(@result, @variables['format'])
      @result = replace_values(@result, @variables.select { |k, _v| k =~ /^replace_values_\d+/ })
      @result = filter_columns(@result, @variables['filter_columns'])
      @result = transpose(@result, @variables['transpose'])
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This class provides a default webhook implementation for report events. It sends out
  # a webrequest to the configured +callback_url+ with all necessary information about the
  # event and the report.
  class ReportWebhook
    def initialize(callback_url)
      @callback_url = callback_url
    end

    # Implements the call of the configured webhook.
    # Provides the following report information in JSON format:
    #
    #   :object_id      - id of the current report
    #   :path           - file path to the report
    #   :status         - report status as string, e.g. `cancelled`, `finished` or `in progress`
    #   :execution_time - execution time in seconds of the report
    #   :template       - name of the used template
    #   :start_time     - time when the report creation started
    #   :end_time       - time when the report creation ended
    #   :event          - event, which has happened, e.g. `on-before-create`
    #
    # Please note that this callback is a non-blocking event, i.e. the report
    # generation is proceeding, no matter if the callback is successfull and
    # no matter how long the execution of the callback does take.
    def callback(event, report)
      # build report information as JSON
      data = { object_id: report.object_id, path: report.path, status: report.status,
               execution_time: report.execution_time, template: report.template,
               start_time: report.start_time, end_time: report.end_time, event: event }

      request = { body: JSON.generate(data), accept: nil, content_type: nil }
      res = ::Grafana::WebRequest.new(@callback_url, request).execute

      "#{res} - Body: #{res.body}"
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # Implements a datasource to return environment related information about the reporter in a tabular format.
  class ReporterEnvironmentDatasource < ::Grafana::AbstractDatasource
    # @see AbstractDatasource#request
    def request(query_description)
      {
        header: ['Version', 'Release Date'],
        content: [[GRAFANA_REPORTER_VERSION.join('.'), GRAFANA_REPORTER_RELEASE_DATE]]
      }
    end

    # @see AbstractDatasource#default_variable_format
    def default_variable_format
      nil
    end

    # @see AbstractDatasource#name
    def name
      self.class.to_s
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Asciidoctor
    # Implements a default table format strategy, which will return tables
    # as asciidoctor formatted table.
    class AdocPlainTableFormatStrategy < AbstractTableFormatStrategy
      # @see AbstractTableFormatStrategy#abbreviation
      def self.abbreviation
        'adoc_plain'
      end

      # @see AbstractTableFormatStrategy#format_rules
      def format_rules
        {
          row_start: '| ',
          row_end: "\n",
          cell_start: '',
          between_cells: ' | ',
          cell_end: '',
          replace_string_or_regex: '|',
          replacement: '\\|'
        }
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Asciidoctor
    # This module contains common methods for all asciidoctor extensions.
    module ProcessorMixin
      # Used when initializing a object instance, to set the report object, which is currently in progress.
      # @param report [GrafanaReporter::Asciidoctor::Report] current report
      # @return [::Asciidoctor::Extensions::Processor] self
      def current_report(report)
        @report = report
        self
      end

      # This method is called if a demo report shall be built for the given {Grafana::Panel}.
      # @param panel [Grafana::Panel] panel object, for which a demo entry shall be created.
      # @return [String] String containing the entry, or nil if not possible for given panel
      def build_demo_entry(panel)
        raise NotImplementedError
      end

      # Merges the given hashes to a common attribute Hash. It respects the priorities of the hashes and the
      # object and allows only valid variables to be used.
      # @param document_hash [Hash] variables from report template level
      # @param item_hash [Hash] variables from item configuration level, i.e. specific call, which may override document
      # @return [Hash] containing accepted variable names including values
      def build_attribute_hash(document_hash, item_hash)
        result = {}

        result['grafana_report_timestamp'] = document_hash['localdatetime']
        result.merge!(document_hash.select do |k, _v|
          k =~ /^var-/ ||
          k =~ /^(?:from|to)$/ ||
          k =~ /^grafana_default_(?:from_timezone|to_timezone|timeout)$/
        end)

        result.merge!(item_hash.select do |k, _v|
          # TODO: specify accepted options for each processor class individually
          k =~ /^(?:var-|render-)/ ||
          k =~ /^(?:timeout|from|to)$/ ||
          k =~ /filter_columns|format|replace_values_.*|transpose|from_timezone|
               to_timezone|result_type|query|table_formatter|include_headline|
               column_divider|row_divider|instant|interval|verbose_log/x
        end)

        result
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_alerts[<options>]
    #
    # Returns the results of alerts query as a asciidoctor table.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # == Supported options
    # +columns+ - see {AlertsTableQuery#pre_process} (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to query for, empty string if no filter is wanted
    #
    # +panel+ - id of the panel to query for
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # +format+ - see {AbstractQuery#format_columns}
    #
    # +replace_values+ - see {AbstractQuery#replace_values}
    #
    # +filter_columns+ - see {AbstractQuery#filter_columns}
    class AlertsTableIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_alerts'
      end

      # :nodoc:
      def process(doc, reader, _target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || doc.attr('grafana_default_instance') || 'default'
        dashboard_id = attrs['dashboard'] || doc.attr('grafana_default_dashboard')
        panel_id = attrs['panel']
        @report.logger.debug("Processing AlertsTableIncludeProcessor (instance: #{instance},"\
                             " dashboard: #{dashboard_id}, panel: #{panel_id})")

        grafana_obj = @report.grafana(instance)
        grafana_obj = @report.grafana(instance).dashboard(dashboard_id) if dashboard_id
        grafana_obj = grafana_obj.panel(panel_id) if panel_id

        vars = { 'table_formatter' => 'adoc_plain' }.merge(build_attribute_hash(doc.attributes, attrs))
        query = AlertsTableQuery.new(grafana_obj, variables: vars)
        defaults = {}
        defaults['dashboardId'] = dashboard_id if dashboard_id
        defaults['panelId'] = panel_id if panel_id

        selected_attrs = attrs.select do |k, _v|
          k =~ /(?:columns|limit|folderId|dashboardId|panelId|dahboardTag|dashboardQuery|state|query)/x
        end
        query.raw_query = defaults.merge(selected_attrs.each_with_object({}) { |(k, v), h| h[k] = v })

        begin
          reader.unshift_lines query.execute.split("\n")
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          reader.unshift_line "|#{e.message}"
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          reader.unshift_line "|#{e.message}\n#{e.backtrace.join("\n")}"
        end

        reader
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(_panel)
        "|===\ninclude::grafana_alerts[columns=\"panelId,name,state\"]\n|==="
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_annotations[<options>]
    #
    # Returns the results of alerts query as a asciidoctor table.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # == Supported options
    # +columns+ - see {AnnotationsTableQuery#pre_process} (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to query for, empty string if no filter is wanted
    #
    # +panel+ - id of the panel to query for
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # +format+ - see {AbstractQuery#format_columns}
    #
    # +replace_values+ - see {AbstractQuery#replace_values}
    #
    # +filter_columns+ - see {AbstractQuery#filter_columns}
    class AnnotationsTableIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_annotations'
      end

      # :nodoc:
      def process(doc, reader, _target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || doc.attr('grafana_default_instance') || 'default'
        dashboard_id = attrs['dashboard'] || doc.attr('grafana_default_dashboard')
        panel_id = attrs['panel']
        @report.logger.debug("Processing AnnotationsTableIncludeProcessor (instance: #{instance})")

        grafana_obj = @report.grafana(instance)
        grafana_obj = @report.grafana(instance).dashboard(dashboard_id) if dashboard_id
        grafana_obj = grafana_obj.panel(panel_id) if panel_id

        vars = { 'table_formatter' => 'adoc_plain' }.merge(build_attribute_hash(doc.attributes, attrs))
        query = AnnotationsTableQuery.new(grafana_obj, variables: vars)
        defaults = {}
        defaults['dashboardId'] = dashboard_id if dashboard_id
        defaults['panelId'] = panel_id if panel_id

        selected_attrs = attrs.select do |k, _v|
          k =~ /(?:columns|limit|alertId|dashboardId|panelId|userId|type|tags)/
        end
        query.raw_query = defaults.merge(selected_attrs.each_with_object({}) { |(k, v), h| h[k] = v })

        begin
          reader.unshift_lines query.execute.split("\n")
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          reader.unshift_line "|#{e.message}"
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          reader.unshift_line "|#{e.message}\n#{e.backtrace.join("\n")}"
        end

        reader
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(_panel)
        "|===\ninclude::grafana_annotations[columns=\"time,panelId,newState,prevState,text\"]\n|==="
      end
    end
  end
end

# frozen_string_literal: true

require 'yaml'

module GrafanaReporter
  module Asciidoctor
    # This class generates the functional help documentation for the asciidoctor report.
    # It can create the documentation for github markdown, as well as in asciidoctor syntax.
    class Help
      # @param headline_level [Integer] top level of headline
      # @return [String] asciidoctor compatible documentation
      def asciidoctor(headline_level = 2)
        help_text(asciidoctor_options.merge(level: headline_level))
      end

      # @param headline_level [Integer] top level of headline
      # @return [String] github markdown compatible documentation
      def github(headline_level = 2)
        "#{toc}\n\n#{help_text(github_options.merge(level: headline_level))}"
      end

      private

      def github_options
        { headline_separator: '#', code_begin: '`', code_end: '`', table_begin: "\n", head_postfix_col: '| -- ',
          table_linebreak: "<br />"}
      end

      def asciidoctor_options
        { headline_separator: '=', code_begin: '`+', code_end: '+`', table_begin: "\n[%autowidth.stretch, "\
          "options=\"header\"]\n|===\n", table_end: "\n|===", table_linebreak: "\n\n" }
      end

      def help_text(opts)
        %(#{opts[:headline_separator] * opts[:level]} Global options
#{global_options_as_text(opts.merge(level: opts[:level] + 1))}
#{opts[:headline_separator] * opts[:level]} Functions
#{functions_as_text(opts.merge(level: opts[:level] + 1))})
      end

      def toc
        result = []

        result << 'Table of contents'
        result << '* [Global options](#global-options)'
        prepared_help[:global_options].sort.map do |k, _v|
          result << "  * [#{k}](##{k.downcase})"
        end

        result << '* [Functions](#functions)'
        prepared_help[:functions].sort.map do |k, _v|
          result << "  * [#{k}](##{k.downcase})"
        end

        result.join("\n")
      end

      def global_options_as_text(opts = {})
        opts = { level: 3 }.merge(opts)
        result = []

        prepared_help[:global_options].sort.map do |k, v|
          result << %(
#{opts[:headline_separator] * opts[:level]} #{opts[:code_begin]}#{k}#{opts[:code_end]}
Usage: #{opts[:code_begin]}#{v['call']}#{opts[:code_end]}

#{v['description']}
)
        end

        result.join
      end

      def functions_as_text(opts = {})
        opts = { level: 3, headline_separator: '=' }.merge(opts)
        result = []

        prepared_help[:functions].sort.map do |k, v|
          result << %(
#{opts[:headline_separator] * opts[:level]} #{opts[:code_begin]}#{k}#{opts[:code_end]}
Usage: #{opts[:code_begin]}#{v[:call]}#{opts[:code_end]}

#{v[:description]}#{"\n\nSee also: #{v[:see]}" if v[:see]}#{unless v[:options].empty?
%(
#{opts[:table_begin]}| Option | Description#{"\n#{opts[:head_postfix_col] * 2}" if opts[:head_postfix_col]}
#{v[:options].sort.map { |_opt_k, opt_v| "| #{opts[:code_begin]}#{opt_v[:call]}#{opts[:code_end]} | #{opt_v[:description].gsub('|', '\|')}#{"#{opts[:table_linebreak]}See also: #{opt_v[:see]}" if opt_v[:see]}" }.join("\n") }#{opts[:table_end]})
end}
)
        end

        result.join
      end

      def prepared_help
        yaml = YAML.safe_load(raw_help_yaml)

        result = {}
        result[:functions] = {}
        result[:global_options] = yaml['global_options']

        functions = result[:functions]
        std_opts = yaml['standard_options']
        yaml.reject { |k, _v| k =~ /.*_options$/ }.each_key do |key|
          functions[key] = {}
          res_item = functions[key]
          res_item[:options] = {}

          item = yaml[key]
          res_item[:call] = item['call']
          res_item[:description] = item['description']
          res_item[:see] = item['see']

          opts = ((item['options'] ? item['options'].keys : []) +
                  (item['standard_options'] ? item['standard_options'].keys : [])).sort
          opts.each do |opt_key|
            res_item[:options][opt_key] = {}

            if std_opts.key?(opt_key)
              res_item[:options][opt_key][:call] = std_opts[opt_key]['call']
              res_item[:options][opt_key][:description] = "#{std_opts[opt_key]['description']} "\
                                                          "#{item['standard_options'][opt_key]}".chop
              res_item[:options][opt_key][:see] = std_opts[opt_key]['see'] if std_opts[opt_key]['see']
            else
              res_item[:options][opt_key][:call] = item['options'][opt_key]['call']
              res_item[:options][opt_key][:description] = item['options'][opt_key]['description']
              res_item[:options][opt_key][:see] = item['options'][opt_key]['see'] if item['options'][opt_key]['see']
            end
          end
        end

        result
      end

      def raw_help_yaml
        <<~YAML_HELP
          global_options:
            grafana_default_instance:
              call: ":grafana_default_instance: <instance_name>"
              description: >-
                Specifies which grafana instance shall be used. If not set, the grafana instance names `default`
                will be used.

            grafana_default_dashboard:
              call: ":grafana_default_dashboard: <dashboard_uid>"
              description: >-
                Specifies to which dashboard the queries shall be targeted by default.

            grafana_default_from_timezone:
              call: ":grafana_default_from_timezone: <timezone>"
              description: Specifies which timezone shall be used for the `from` time, e.g. `CET` or `CEST`.

            grafana_default_to_timezone:
              call: ":grafana_default_to_timezone: <timezone>"
              description: Specifies which timezone shall be used for the `to` time, e.g. `CET` or `CEST`.

            from:
              call: ":from: <from_timestamp>"
              description: >-
                Overrides the time setting from grafana. It may contain dates as `now-1M/M`, which will be translated
                properly to timestamps relative to the called time.

            to:
              call: ":to: <to_timestamp>"
              description: >-
                Overrides the time setting from grafana. It may contain dates as `now-1M/M`, which will be translated
                properly to timestamps relative to the called time.

          standard_options:
            instance:
              call: instance="<instance_name>"
              description: >-
                can be used to override global grafana instance, set in the report with `grafana_default_instance`.
                If nothing is set, the configured grafana instance with name `default` will be used.

            dashboard:
              call: dashboard="<dashboard_uid>"
              description: >-
                Specifies the dashboard to be used. If `grafana_default_dashboard` is specified in the report template,
                this value can be overridden with this option.

            from:
              call: from="<timestamp>"
              description: can be used to override default `from` time

            from_timezone:
              call: from_timezone="<timezone>"
              description: can be used to override system timezone for `from` time and will also override `grafana_default_from_timezone` option

            to_timezone:
              call: to_timezone="<timezone>"
              description: can be used to override system timezone for `to` time and will also override `grafana_default_to_timezone` option

            to:
              call: to="<timestamp>"
              description: can be used to override default `to` time

            format:
              call: format="<format_col1>,<format_col2>,..."
              description: >-
                Specify format in which the results in a specific column shall be returned, e.g. `%.2f` for only
                two digit decimals of a float. Several column formats are separated by `,`, i.e. `%.2f,%.3f` would
                apply `%.2f` to the first column and `%.3f` to the second column. All other columns would not be
                formatted. You may also format time in milliseconds to a time format by specifying e.g. `date:iso`.
                Commas in format strings are supported, but have to be escaped by using `_,`.
                Execution of related functions is applied in the following order `format`,
                `replace_values`, `filter_columns`, `transpose`.
              see: 'https://ruby-doc.org/core/Kernel.html#method-i-sprintf'

            replace_values:
              call: replace_values="<replace_1>:<with_1>,<replace_2>:<with_2>,..."
              description: >-
                Specify result values which shall be replaced, e.g. `2:OK` will replace query values `2` with value `OK`.
                Replacing several values is possible by separating by `,`. Matches with regular expressions are also
                supported, but must be full matches, i.e. have to start with `^` and end with `$`, e.g. `^[012]$:OK`.
                Number replacements can also be performed, e.g. `<8.2` or `<>3`. Execution of related functions is
                applied in the following order `format`,
                `replace_values`, `filter_columns`, `transpose`.
              see: https://ruby-doc.org/core/Regexp.html#class-Regexp-label-Character+Classes

            include_headline:
              call: include_headline="true"
              description: >-
                Adds the headline of the columns as first row of the resulting table.

            filter_columns:
              call: filter_columns="<column_name_1>,<column_name_2>,..."
              description: >-
                Removes specified columns from result.  Commas in format strings are supported, but have to be
                escaped by using `_,`. Execution of related functions is applied in the following order
                `format`, `replace_values`, `filter_columns`, `transpose`.

            transpose:
              call: transpose="true"
              description: >-
                Transposes the query result, i.e. columns become rows and rows become columnns. Execution of related
                functions is applied in the following order `format`, `replace_values`, `filter_columns`,
                `transpose`.

            column_divider:
              call: column_divider="<divider>"
              description: >-
                Replace the default column divider with another one, when used in conjunction with `table_formatter` set to
                `adoc_deprecated`. Defaults to ` | ` for being interpreted as a asciidoctor column. DEPRECATED: switch to
                `table_formatter` named `adoc_plain`, or implement a custom table formatter.

            row_divider:
              call: row_divider="<divider>"
              description: >-
                Replace the default row divider with another one, when used in conjunction with `table_formatter` set to
                `adoc_deprecated`. Defaults to `| ` for being interpreted as a asciidoctor row. DEPRECATED: switch to
                `table_formatter` named `adoc_plain`, or implement a custom table formatter.

            table_formatter:
              call: table_formatter="<formatter>"
              description: >-
                Specify a table formatter fitting for your expected target format. It defaults to `adoc_plain` for asciidoctor
                templates and to `csv` for all other templates, e.g. ERB.

            timeout:
              call: timeout="<timeout_in_seconds>"
              description: >-
                Set a timeout for the current query. If not overridden with `grafana_default_timeout` in the report template,
                this defaults to 60 seconds.

            interval:
              call: interval="<intervaL>"
              description: >-
                Used to set the interval size for timescale datasources, whereas the value is used without further
                conversion directly in the datasource specific interval parameter.
                Prometheus default: 15 (passed as `step` parameter)
                Influx default: similar to grafana default, i.e. `(to_time - from_time) / 1000`
                (replaces `interval_ms` and `interval` variables in query)

            instant:
              call: instant="true"
              description: >-
                Optional parameter for Prometheus `instant` queries. Ignored for other datasources than Prometheus.

            verbose_log:
              call: verbose_log="true"
              description: >-
                Setting this option will show additional information about the returned query results in the log as
                DEBUG messages.

          # ----------------------------------
          # FUNCTION DOCUMENTATION STARTS HERE
          # ----------------------------------

          grafana_help:
            description: Show all available grafana calls within the asciidoctor templates, including available options.
            call: 'include::grafana_help[]'

          grafana_environment:
            description: >-
              Shows all available variables in the rendering context which can be used in the asciidoctor template.
              If optional `instance` is specified, additional information about the configured grafana instance will be provided.
              This is especially helpful for debugging.
            call: 'include::grafana_environment[]'
            standard_options:
              instance:

          grafana_alerts:
            description: >-
              Returns a table of active alert states including the specified columns and the connected information. Supports
              all query parameters from the Grafana Alerting API, such as `query`, `state`, `limit`, `folderId` and others.
            call: 'include::grafana_alerts[columns="<column_name_1>,<column_name_2>,...",options]'
            see: https://grafana.com/docs/grafana/latest/http_api/alerting/#get-alerts
            options:
              columns:
                description: >-
                  Specifies columns that shall be returned. Valid columns are `id`, `dashboardId`, `dashboardUId`, `dashboardSlug`,
                  `panelId`, `name`, `state`, `newStateDate`, `evalDate`, `evalData` and `executionError`.
                call: columns="<column_name_1>,<columns_name_2>,..."
              panel:
                description: >-
                  If specified, the resulting alerts are filtered for this panel. This option will only work, if a `dashboard`
                  or `grafana_default_dashboard` is set.
                call: panel="<panel_id>"
            standard_options:
              column_divider:
              dashboard: >-
                If this option, or the global option `grafana_default_dashboard` is set, the resulting alerts will be limited to
                this dashboard. To show all alerts in this case, specify `dashboard=""` as option.
              filter_columns:
              format:
              from:
              include_headline:
              instance:
              replace_values:
              row_divider:
              table_formatter:
              timeout:
              to:
              transpose:
              from_timezone:
              to_timezone:

          grafana_annotations:
            description: >-
              Returns a table of all annotations, matching the specified filter criteria and the specified columns. Supports all
              query parameters from the Grafana Alerting API, such as `limit`, `alertId`, `panelId` and others.
            call: 'include::grafana_annotations[columns="<column_name_1>,<column_name_2>,...",options]'
            see: https://grafana.com/docs/grafana/latest/http_api/annotations/#find-annotations
            options:
              columns:
                description: >-
                  Specified the columns that shall be returned. Valid columns are `id`, `alertId`, `dashboardId`, `panelId`, `userId`,
                  `userName`, `newState`, `prevState`, `time`, `timeEnd`, `text`, `metric` and `type`.
                call: columns="<column_name_1>,<columns_name_2>,..."
              panel:
                description: >-
                  If specified, the resulting alerts are filtered for this panel. This option will only work, if a `dashboard` or
                  `grafana_default_dashboard` is set.
                call: panel="<panel_id>"
            standard_options:
              column_divider:
              dashboard: >-
                If this option, or the global option `grafana_default_dashboard` is set, the resulting alerts will be limited to this
                dashboard. To show all alerts in this case, specify `dashboard=""` as option.
              filter_columns:
              format:
              from:
              include_headline:
              instance:
              replace_values:
              row_divider:
              table_formatter:
              timeout:
              to:
              transpose:
              from_timezone:
              to_timezone:

          grafana_panel_property:
            description: >-
              Returns a property field for the specified panel. `<type>` can either be `title` or `description`.
              Grafana variables will be replaced in the returned value.
            call: 'grafana_panel_property:<panel_id>["<type>",options]'
            see: https://grafana.com/docs/grafana/latest/variables/syntax/
            standard_options:
              dashboard:
              instance:

          grafana_panel_image:
            description: Includes a panel image as an image in the document. Can be called for inline-images as well as for blocks.
            call: 'grafana_panel_image:<panel_id>[options] or grafana_panel_image::<panel_id>[options]'
            options:
              render-height:
                description: can be used to override default `height` in which the panel shall be rendered
                call: render-height="<height>"
              render-width:
                description: can be used to override default `width` in which the panel shall be rendered
                call: render-width="<width>"
              render-scale:
                description: can be used to override default scale in which the panel shall be rendered
                call: render-scale="<scale>"
              render-theme:
                description: can be used to override default `theme` in which the panel shall be rendered (light by default)
                call: render-theme="<theme>"
              render-timeout:
                description: can be used to override default `timeout` in which the panel shall be rendered (60 seconds by default)
                call: render-timeout="<timeout>"
            standard_options:
              dashboard:
              from:
              instance:
              timeout:
              to:
              from_timezone:
              to_timezone:

          grafana_panel_query_table:
            description: >-
              Returns the results of a query, which is configured in a grafana panel, as a table in asciidoctor.
              Grafana variables will be replaced in the panel's SQL statement.
            call: 'include::grafana_panel_query_table:<panel_id>[query="<query_letter>",options]'
            see: https://grafana.com/docs/grafana/latest/variables/syntax/
            options:
              query:
                call: query="<query_letter>"
                description: +<query_letter>+ needs to point to the grafana query which shall be evaluated, e.g. +A+ or +B+.
            standard_options:
              column_divider:
              dashboard:
              filter_columns:
              format:
              from:
              include_headline:
              instance:
              replace_values:
              row_divider:
              table_formatter:
              timeout:
              to:
              transpose:
              from_timezone:
              to_timezone:
              instant:
              interval:
              verbose_log:

          grafana_panel_query_value:
            call: 'grafana_panel_query_value:<panel_id>[query="<query_letter>",options]'
            description: >-
              Returns the value in the first column and the first row of a query, which is configured in a grafana panel.
              Grafana variables will be replaced in the panel's SQL statement.
            see: https://grafana.com/docs/grafana/latest/variables/syntax/
            options:
              query:
                call: query="<query_letter>"
                description: +<query_letter>+ needs to point to the grafana query which shall be evaluated, e.g. +A+ or +B+.
            standard_options:
              dashboard:
              filter_columns:
              format:
              from:
              instance:
              replace_values:
              timeout:
              to:
              from_timezone:
              to_timezone:
              instant:
              interval:
              verbose_log:

          grafana_sql_table:
            call: 'include::grafana_sql_table:<datasource_id>[sql="<sql_query>",options]'
            description: >-
              Returns a table with all results of the given query.
              Grafana variables will be replaced in the SQL statement.
            see: https://grafana.com/docs/grafana/latest/variables/syntax/
            standard_options:
              column_divider:
              filter_columns:
              format:
              from:
              include_headline:
              instance:
              replace_values:
              row_divider:
              table_formatter:
              timeout:
              to:
              transpose:
              from_timezone:
              to_timezone:
              instant:
              interval:
              verbose_log:

          grafana_sql_value:
            call: 'grafana_sql_value:<datasource_id>[sql="<sql_query>",options]'
            description: >-
              Returns the value in the first column and the first row of the given query.
              Grafana variables will be replaced in the SQL statement.

              Please note that asciidoctor might fail, if you use square brackets in your
              sql statement. To overcome this issue, you'll need to escape the closing
              square brackets, i.e. +]+ needs to be replaced with +\\]+.
            see: https://grafana.com/docs/grafana/latest/variables/syntax/
            standard_options:
              filter_columns:
              format:
              from:
              instance:
              replace_values:
              timeout:
              to:
              from_timezone:
              to_timezone:
              instant:
              interval:
              verbose_log:

          grafana_value_as_variable:
            call: 'include::grafana_value_as_variable[call="<grafana_reporter_call>",variable_name="<your_variable_name>",options]'
            description: >-
              Executes the given +<grafana_reporter_call>+ and stored the resulting value
              in the given +<your_variable_name>+, so that it can be used in asciidoctor
              at any position with +{<your_variable_name>}+.

              A sample call could look like this: +include:grafana_value_as_variable[call="grafana_sql_value:1",variable_name="my_variable",sql="SELECT 'looks good'",<any_other_option>]+

              If the function succeeds, it will add this to the asciidoctor file:

              +:my_variable: looks good+

              Please note, that you may add any other option to the call. These will
              simply be passed 1:1 to the +<grafana_reporter_call>+.
            options:
              call:
                call: call="<grafana_reporter_call>"
                description: Call to grafana reporter function, for which the result shall be stored as variable. Please note that only functions without +include::+ are supported here.
              variable_name:
                call: variable_name="<your_variable_name>"
                description: Name of the variable, which will get the value assigned.
        YAML_HELP
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   grafana_panel_image::<panel_id>[<options>]
    #
    # Stores the queried panel as a temporary image file and returns a relative asciidoctor link
    # to the storage location, which can then be included in the report.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # == Supported options
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    class PanelImageBlockMacro < ::Asciidoctor::Extensions::BlockMacroProcessor
      include ProcessorMixin
      use_dsl

      named :grafana_panel_image

      # :nodoc:
      def process(parent, target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || parent.document.attr('grafana_default_instance') || 'default'
        dashboard = attrs['dashboard'] || parent.document.attr('grafana_default_dashboard')
        @report.logger.debug("Processing PanelImageBlockMacro (instance: #{instance}, dashboard: #{dashboard},"\
                             " panel: #{target})")

        begin
          query = PanelImageQuery.new(@report.grafana(instance).dashboard(dashboard).panel(target),
                                      variables: build_attribute_hash(parent.document.attributes, attrs))

          image = query.execute
          image_path = @report.save_image_file(image)
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          return create_paragraph(parent, e.message, attrs)
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          return create_paragraph(parent, e.message, attrs)
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          return create_paragraph(parent, "#{e.message}\n#{e.backtrace.join("\n")}", attrs)
        end

        attrs['target'] = image_path
        create_image_block(parent, attrs)
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'] == 'graph'

        "grafana_panel_image::#{panel.id}[dashboard=\"#{panel.dashboard.id}\",width=\"50%\"]"
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   grafana_panel_image:<panel_id>[<options>]
    #
    # Stores the queried panel as a temporary image file and returns a relative asciidoctor link
    # to the storage location, which can then be included in the report.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # == Supported options
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    class PanelImageInlineMacro < ::Asciidoctor::Extensions::InlineMacroProcessor
      include ProcessorMixin
      use_dsl

      named :grafana_panel_image

      # :nodoc:
      def process(parent, target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || parent.document.attr('grafana_default_instance') || 'default'
        dashboard = attrs['dashboard'] || parent.document.attr('grafana_default_dashboard')
        @report.logger.debug("Processing PanelImageInlineMacro (instance: #{instance}, dashboard: #{dashboard},"\
                             " panel: #{target})")

        begin
          # set alt text to a default, because otherwise asciidoctor fails
          attrs['alt'] = '' unless attrs['alt']
          query = PanelImageQuery.new(@report.grafana(instance).dashboard(dashboard).panel(target),
                                      variables: build_attribute_hash(parent.document.attributes, attrs))

          image = query.execute
          image_path = @report.save_image_file(image)
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          return create_inline(parent, :quoted, e.message)
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          return create_inline(parent, :quoted, e.message)
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          return create_inline(parent, :quoted, "#{e.message}\n#{e.backtrace.join("\n")}")
        end

        create_inline(parent, :image, nil, { target: image_path, attributes: attrs })
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'] == 'graph'

        "see here: grafana_panel_image:#{panel.id}[dashboard=\"#{panel.dashboard.id}\","\
        'width="90%"] - a working inline image'
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   grafana_panel_property:<panel_id>[<options>]
    #
    # Returns the requested panel property.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # == Supported options
    # +field+ - property to query for, e.g. +description+ or +title+ (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to use
    class PanelPropertyInlineMacro < ::Asciidoctor::Extensions::InlineMacroProcessor
      include ProcessorMixin
      use_dsl

      named :grafana_panel_property
      name_positional_attributes :field

      # :nodoc:
      def process(parent, target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || parent.document.attr('grafana_default_instance') || 'default'
        dashboard = attrs['dashboard'] || parent.document.attr('grafana_default_dashboard')
        @report.logger.debug("Processing PanelPropertyInlineMacro (instance: #{instance}, dashboard: #{dashboard},"\
                             " panel: #{target}, property: #{attrs[:field]})")

        begin
          query = PanelPropertyQuery.new(@report.grafana(instance).dashboard(dashboard).panel(target),
                                         variables: build_attribute_hash(parent.document.attributes, attrs))
          query.raw_query = { property_name: attrs[:field] }

          description = query.execute
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          return create_inline(parent, :quoted, e.message)
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          return create_inline(parent, :quoted, e.message)
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          return create_inline(parent, :quoted, "#{e.message}\n#{e.backtrace.join("\n")}")
        end

        # translate linebreaks to asciidoctor syntax
        # and HTML encode to make sure, that HTML formattings are respected
        create_inline(parent, :quoted, CGI.escapeHTML(description.gsub(%r{//[^\n]*(?:\n)?}, '').gsub(/\n/, " +\n")))
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['title']
        return nil if panel.model['title'].strip == ''
        return nil if panel.model['title'].strip == 'Panel Title'

        "this text includes the panel with title grafana_panel_property:#{panel.id}[\"title\","\
        "dashboard=\"#{panel.dashboard.id}\"]"
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_panel_query_table:<panel_id>[<options>]
    #
    # Returns the results of the SQL query as a asciidoctor table.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # All other variables starting with +var-+ will be used to replace grafana templating strings
    # in the given SQL query.
    #
    # == Supported options
    # +query+ - query letter, which shall be used, e.g. +C+ (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # +format+ - see {AbstractQuery#format_columns}
    #
    # +replace_values+ - see {AbstractQuery#replace_values}
    #
    # +filter_columns+ - see {AbstractQuery#filter_columns}
    class PanelQueryTableIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_panel_query_table:'
      end

      # :nodoc:
      def process(doc, reader, target, attrs)
        return if @report.cancel

        @report.next_step
        panel_id = target.split(':')[1]
        instance = attrs['instance'] || doc.attr('grafana_default_instance') || 'default'
        dashboard = attrs['dashboard'] || doc.attr('grafana_default_dashboard')
        attrs['result_type'] = 'panel_table'
        @report.logger.debug("Processing PanelQueryTableIncludeProcessor (instance: #{instance}, "\
                             "dashboard: #{dashboard}, panel: #{panel_id}, query: #{attrs['query']})")

        begin
          panel = @report.grafana(instance).dashboard(dashboard).panel(panel_id)
          vars = { 'table_formatter' => 'adoc_plain' }.merge(build_attribute_hash(doc.attributes, attrs))
          query = QueryValueQuery.new(panel, variables: vars)

          reader.unshift_lines query.execute.split("\n")
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          reader.unshift_line "|#{e.message}"
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          reader.unshift_line "|#{e.message}"
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          reader.unshift_line "|#{e.message}\n#{e.backtrace.join("\n")}"
        end

        reader
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'].include?('table')

        ref_id = nil
        panel.model['targets'].each do |item|
          if !item['hide'] && !panel.query(item['refId']).to_s.empty?
            ref_id = item['refId']
            break
          end
        end
        return nil unless ref_id

        "|===\ninclude::grafana_panel_query_table:#{panel.id}[query=\"#{ref_id}\",filter_columns=\"time\","\
        "dashboard=\"#{panel.dashboard.id}\"]\n|==="
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   grafana_panel_query_value:<panel_id>[<options>]
    #
    # Returns the first value of the resulting SQL query.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +grafana_default_dashboard+ - uid of grafana default dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # All other variables starting with +var-+ will be used to replace grafana templating strings
    # in the given SQL query.
    #
    # == Supported options
    # +query+ - query letter, which shall be used, e.g. +C+ (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +dashboard+ - uid of grafana dashboard to use
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # +format+ - see {AbstractQuery#format_columns}
    #
    # +replace_values+ - see {AbstractQuery#replace_values}
    #
    # +filter_columns+ - see {AbstractQuery#filter_columns}
    class PanelQueryValueInlineMacro < ::Asciidoctor::Extensions::InlineMacroProcessor
      include ProcessorMixin
      use_dsl

      named :grafana_panel_query_value

      # :nodoc:
      def process(parent, target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || parent.document.attr('grafana_default_instance') || 'default'
        dashboard = attrs['dashboard'] || parent.document.attr('grafana_default_dashboard')
        attrs['result_type'] = 'panel_value'
        @report.logger.debug("Processing PanelQueryValueInlineMacro (instance: #{instance}, dashboard: #{dashboard},"\
                             " panel: #{target}, query: #{attrs['query']})")

        begin
          panel = @report.grafana(instance).dashboard(dashboard).panel(target)
          query = QueryValueQuery.new(panel, variables: build_attribute_hash(parent.document.attributes, attrs))

          create_inline(parent, :quoted, query.execute)
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          create_inline(parent, :quoted, e.message)
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          create_inline(parent, :quoted, e.message)
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          create_inline(parent, :quoted, "#{e.message}\n#{e.backtrace.join("\n")}")
        end
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'] == 'singlestat'

        ref_id = nil
        panel.model['targets'].each do |item|
          if !item['hide'] && !panel.query(item['refId']).to_s.empty?
            ref_id = item['refId']
            break
          end
        end
        return nil unless ref_id

        "it's easily possible to include the query value: grafana_panel_query_value:#{panel.id}[query=\"#{ref_id}\""\
        ",dashboard=\"#{panel.dashboard.id}\"] - just within this text."
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This module contains all classes, which are necessary to use the reporter in conjunction with asciidoctor.
  module Asciidoctor
    # Implementation of a specific {AbstractReport}. It is used to
    # build reports specifically for asciidoctor results.
    class Report < ::GrafanaReporter::AbstractReport
      # @see AbstractReport#initialize
      def initialize(config)
        super
        @image_files = []
      end

      # Starts to create an asciidoctor report. It utilizes all extensions in the {GrafanaReporter::Asciidoctor}
      # namespace to realize the conversion.
      # @see AbstractReport#build
      def build
        attrs = { 'convert-backend' => 'pdf' }.merge(@config.default_document_attributes.merge(@custom_attributes))
        logger.debug("Document attributes: #{attrs}")

        initialize_step_counter

        # register necessary extensions for the current report
        ::Asciidoctor::LoggerManager.logger = logger

        registry = ::Asciidoctor::Extensions::Registry.new
        registry.inline_macro PanelImageInlineMacro.new.current_report(self)
        registry.inline_macro PanelQueryValueInlineMacro.new.current_report(self)
        registry.inline_macro PanelPropertyInlineMacro.new.current_report(self)
        registry.inline_macro SqlValueInlineMacro.new.current_report(self)
        registry.block_macro PanelImageBlockMacro.new.current_report(self)
        registry.include_processor ValueAsVariableIncludeProcessor.new.current_report(self)
        registry.include_processor PanelQueryTableIncludeProcessor.new.current_report(self)
        registry.include_processor SqlTableIncludeProcessor.new.current_report(self)
        registry.include_processor ShowEnvironmentIncludeProcessor.new.current_report(self)
        registry.include_processor ShowHelpIncludeProcessor.new.current_report(self)
        registry.include_processor AnnotationsTableIncludeProcessor.new.current_report(self)
        registry.include_processor AlertsTableIncludeProcessor.new.current_report(self)

        ::Asciidoctor.convert_file(@template, extension_registry: registry, backend: attrs['convert-backend'],
                                              to_file: path, attributes: attrs, header_footer: true)

        # store report including als images as ZIP file, if the result is not a PDF
        if attrs['convert-backend'] != 'pdf'
          # build zip file
          zip_file = Tempfile.new('gf_zip')
          buffer = Zip::OutputStream.write_buffer do |zipfile|
            # add report file
            zipfile.put_next_entry("#{path.gsub(@config.reports_folder, '')}.#{attrs['convert-backend']}")
            zipfile.write File.read(path)

            # add image files
            @image_files.each do |file|
              zipfile.put_next_entry(file.path.gsub(@config.images_folder, ''))
              zipfile.write File.read(file.path)
            end
          end
          File.open(zip_file, 'wb') do |f|
            f.write buffer.string
          end

          # replace original file with zip file
          zip_file.rewind
          begin
            File.write(path, zip_file.read)
          rescue StandardError => e
            logger.fatal("Could not overwrite report file '#{path}' with ZIP file. (#{e.message}).")
          end

          # cleanup temporary zip file
          zip_file.close
          zip_file.unlink
        end

        clean_image_files
      end

      # Called to save a temporary image file. After the final generation of the
      # report, these temporary files will automatically be removed.
      # @param img_data [String] image file raw data, which shall be saved
      # @return [String] path to the temporary file.
      def save_image_file(img_data)
        file = Tempfile.new(['gf_image_', '.png'], @config.images_folder.to_s)
        file.binmode
        file.write(img_data)
        path = file.path.gsub(/#{@config.images_folder}/, '')

        @image_files << file
        file.close

        path
      end

      # @see AbstractReport#default_template_extension
      def self.default_template_extension
        'adoc'
      end

      # @see AbstractReport#default_result_extension
      def self.default_result_extension
        'pdf'
      end

      # @see AbstractReport#demo_report_classes
      def self.demo_report_classes
        [AlertsTableIncludeProcessor, AnnotationsTableIncludeProcessor, PanelImageBlockMacro, PanelImageInlineMacro,
         PanelPropertyInlineMacro, PanelQueryTableIncludeProcessor, PanelQueryValueInlineMacro,
         SqlTableIncludeProcessor, SqlValueInlineMacro, ShowHelpIncludeProcessor, ShowEnvironmentIncludeProcessor]
      end

      private

      def clean_image_files
        @image_files.each(&:unlink)
        @image_files = []
      end

      def initialize_step_counter
        @total_steps = 0
        File.readlines(@template).each do |line|
          begin
            # TODO: move these calls to the specific processors to ensure all are counted properly
            @total_steps += line.gsub(%r{//.*}, '').scan(/(?:grafana_panel_image|grafana_panel_query_value|
                                                         grafana_panel_query_table|grafana_sql_value|
                                                         grafana_sql_table|grafana_environment|grafana_help|
                                                         grafana_panel_property|grafana_annotations|grafana_alerts|
                                                         grafana_value_as_variable)/x).length
          rescue StandardError => e
            logger.error("Could not process line '#{line}' (Error: #{e.message})")
            raise e
          end
        end
        logger.debug("Template #{@template} contains #{@total_steps} calls of grafana reporter functions.")
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_environment[]
    #
    # Shows all available variables, which are accessible during this run of the asciidoctor
    # grafana reporter in a asciidoctor readable form.
    #
    # This processor is very helpful during report template design, to find out the available
    # variables, that can be accessed.
    #
    # == Used document parameters
    # All, to be listed as the available environment.
    #
    # == Supported options
    # +instance+ - grafana instance name, if extended information about the grafana instance shall be printed
    class ShowEnvironmentIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_environment'
      end

      # :nodoc:
      def process(doc, reader, _target, attrs)
        # return if @report.cancel
        @report.next_step
        instance = attrs['instance'] || doc.attr('grafana_default_instance') || 'default'
        attrs['result_type'] = 'sql_table'
        @report.logger.debug('Processing ShowEnvironmentIncludeProcessor')
        grafana = @report.grafana(instance)

        vars = { 'table_formatter' => 'adoc_plain', 'include_headline' => 'true'}
        vars = vars.merge(build_attribute_hash(doc.attributes, attrs))

        # query reporter environment
        result = ['== Reporter', '|===']
        query = QueryValueQuery.new(grafana, variables: vars.merge({'transpose' => 'true'}))
        query.datasource = ::GrafanaReporter::ReporterEnvironmentDatasource.new(nil)
        result += query.execute.split("\n")

        # query grafana environment
        result += ['|===', '',
                   '== Grafana Instance', '|===']
        query = QueryValueQuery.new(grafana, variables: vars.merge({'transpose' => 'true'}))
        query.raw_query = {grafana: grafana, mode: 'general'}
        query.datasource = ::Grafana::GrafanaEnvironmentDatasource.new(nil)
        result += query.execute.split("\n")

        result += ['|===', '',
                   '== Accessible Dashboards', '|===']
        query = QueryValueQuery.new(grafana, variables: vars)
        query.raw_query = {grafana: grafana, mode: 'dashboards'}
        query.datasource = Grafana::GrafanaEnvironmentDatasource.new(nil)
        result += query.execute.split("\n")

        result += ['|===', '',
                   '== Accessible Variables',
                   '|===']
        doc.attributes.sort.each do |k, v|
          result << "| `+{#{k}}+` | #{v}"
        end
        result << '|==='

        reader.unshift_lines result
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(_panel)
        'include::grafana_environment[]'
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_help[]
    #
    # Shows all available options for the asciidoctor grafana reporter in a asciidoctor readable form.
    #
    # == Used document parameters
    # None
    class ShowHelpIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_help'
      end

      # :nodoc:
      def process(_doc, reader, _target, _attrs)
        # return if @report.cancel
        @report.next_step
        @report.logger.debug('Processing ShowHelpIncludeProcessor')

        reader.unshift_lines Help.new.asciidoctor.split("\n")
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(_panel)
        'include::grafana_help[]'
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_sql_table:<datasource_id>[<options>]
    #
    # Returns the results of the SQL query as a asciidoctor table.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # All other variables starting with +var-+ will be used to replace grafana templating strings
    # in the given SQL query.
    #
    # == Supported options
    # +sql+ - sql statement (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # +format+ - see {AbstractQuery#format_columns}
    #
    # +replace_values+ - see {AbstractQuery#replace_values}
    #
    # +filter_columns+ - see {AbstractQuery#filter_columns}
    class SqlTableIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_sql_table:'
      end

      # :nodoc:
      def process(doc, reader, target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || doc.attr('grafana_default_instance') || 'default'
        attrs['result_type'] = 'sql_table'
        @report.logger.debug("Processing SqlTableIncludeProcessor (instance: #{instance},"\
                             " datasource: #{target.split(':')[1]}, sql: #{attrs['sql']})")

        begin
          # catch properly if datasource could not be identified
          vars = { 'table_formatter' => 'adoc_plain' }.merge(build_attribute_hash(doc.attributes, attrs))
          query = QueryValueQuery.new(@report.grafana(instance), variables: vars)
          query.datasource = @report.grafana(instance).datasource_by_id(target.split(':')[1].to_i)
          query.raw_query = attrs['sql']

          reader.unshift_lines query.execute.split("\n")
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          reader.unshift_line "|#{e.message}"
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          reader.unshift_line "|#{e.message}"
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          reader.unshift_line "|#{e.message}\n#{e.backtrace.join("\n")}"
        end

        reader
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'].include?('table')

        ref_id = nil
        panel.model['targets'].each do |item|
          if !item['hide'] && !panel.query(item['refId']).to_s.empty?
            ref_id = item['refId']
            break
          end
        end
        return nil unless ref_id

        "|===\ninclude::grafana_sql_table:#{panel.dashboard.grafana.datasource_by_name(panel.model['datasource']).id}"\
        "[sql=\"#{panel.query(ref_id).gsub(/"/, '\"').gsub("\n", ' ').gsub(/\\/, '\\\\')}\",filter_columns=\"time\","\
        "dashboard=\"#{panel.dashboard.id}\",from=\"now-1h\",to=\"now\"]\n|==="
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   grafana_sql_value:<datasource_id>[<options>]
    #
    # Returns the first value of the resulting SQL query.
    #
    # == Used document parameters
    # +grafana_default_instance+ - name of grafana instance, 'default' if not specified
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # All other variables starting with +var-+ will be used to replace grafana templating strings
    # in the given SQL query.
    #
    # == Supported options
    # +sql+ - sql statement (*mandatory*)
    #
    # +instance+ - name of grafana instance, 'default' if not specified
    #
    # +from+ - 'from' time for the sql query
    #
    # +to+ - 'to' time for the sql query
    #
    # +format+ - see {AbstractQuery#format_columns}
    #
    # +replace_values+ - see {AbstractQuery#replace_values}
    #
    # +filter_columns+ - see {AbstractQuery#filter_columns}
    class SqlValueInlineMacro < ::Asciidoctor::Extensions::InlineMacroProcessor
      include ProcessorMixin
      use_dsl

      named :grafana_sql_value

      # @see GrafanaReporter::Asciidoctor::SqlFirstValueQuery
      def process(parent, target, attrs)
        return if @report.cancel

        @report.next_step
        instance = attrs['instance'] || parent.document.attr('grafana_default_instance') || 'default'
        attrs['result_type'] = 'sql_value'
        sql = attrs['sql']
        @report.logger.debug("Processing SqlValueInlineMacro (instance: #{instance}, datasource: #{target},"\
                             " sql: #{sql})")

        # translate sql statement to fix asciidoctor issue
        # refer https://github.com/asciidoctor/asciidoctor/issues/4072#issuecomment-991305715
        sql_translated = CGI::unescapeHTML(sql) if sql
        if sql != sql_translated
          @report.logger.debug("Translating SQL query to fix asciidoctor issue: #{sql_translated}")
          sql = sql_translated
        end

        begin
          # catch properly if datasource could not be identified
          query = QueryValueQuery.new(@report.grafana(instance),
                                      variables: build_attribute_hash(parent.document.attributes, attrs))
          query.datasource = @report.grafana(instance).datasource_by_id(target)
          query.raw_query = sql

          create_inline(parent, :quoted, query.execute)
        rescue Grafana::GrafanaError => e
          @report.logger.error(e.message)
          create_inline(parent, :quoted, e.message)
        rescue GrafanaReporterError => e
          @report.logger.error(e.message)
          create_inline(parent, :quoted, e.message)
        rescue StandardError => e
          @report.logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
          create_inline(parent, :quoted, "#{e.message}\n#{e.backtrace.join("\n")}")
        end
      end

      # @see ProcessorMixin#build_demo_entry
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'] == 'singlestat'

        ref_id = nil
        panel.model['targets'].each do |item|
          if !item['hide'] && !panel.query(item['refId']).to_s.empty?
            ref_id = item['refId']
            break
          end
        end
        return nil unless ref_id

        "grafana_sql_value:#{panel.dashboard.grafana.datasource_by_name(panel.model['datasource']).id}"\
        "[sql=\"#{panel.query(ref_id).gsub(/"/, '\"').gsub("\n", ' ').gsub(/\\/, '\\\\')}\",from=\"now-1h\","\
        'to="now"]'
      end
    end
  end
end

# frozen_string_literal: true


module GrafanaReporter
  module Asciidoctor
    # Implements the hook
    #   include::grafana_value_as_variable[<options>]
    #
    # Returns an attribute definition in asciidoctor format. This is needed if you want to refer to values of
    # a grafana query within a variable in asciidoctor. As this works without this function for the
    # `IncludeProcessor`s values, it will not work for all the other processors.
    #
    # This method is just a proxy for all other hooks and will forward parameters accordingly.
    #
    # Example:
    #
    #   include:grafana_value_as_variable[call="grafana_sql_value:1",variable_name="my_variable",sql="SELECT 'looks good'",<any_other_option>]
    #
    # This will call the {SqlValueInlineMacro} with `datasource_id` set to `1` and store the result in the
    # variable. The resulting asciidoctor variable definition will be created as:
    #
    #   :my_variable: looks good
    #
    # and can be refered to in your document easily as
    #
    #   {my_variable}
    #
    # == Supported options
    # +call+ - regular call to the reporter hook (*mandatory*)
    #
    # +variable_name+ - name of the variable, to which the result shall be assigned (*mandatory*)
    class ValueAsVariableIncludeProcessor < ::Asciidoctor::Extensions::IncludeProcessor
      include ProcessorMixin

      # :nodoc:
      def handles?(target)
        target.start_with? 'grafana_value_as_variable'
      end

      # :nodoc:
      def process(doc, reader, target, attrs)
        return if @report.cancel

        # increase step for this processor as well as it is also counted in the step counter
        @report.next_step

        call_attr = attrs.delete('call')
        call, target = call_attr.split(':') if call_attr
        attribute = attrs.delete('variable_name')
        @report.logger.debug("Processing ValueAsVariableIncludeProcessor (call: #{call}, target: #{target},"\
                             " variable_name: #{attribute}, attrs: #{attrs})")
        if !call || !attribute
          @report.logger.error('ValueAsVariableIncludeProcessor: Missing mandatory attribute \'call\' or '\
                               '\'variable_name\'.')
          # increase counter, as error occured and no sub call is being processed
          @report.next_step
          return reader
        end

        # TODO: properly show error messages also in document
        ext = doc.extensions.find_inline_macro_extension(call) if doc.extensions.inline_macros?
        if !ext
          @report.logger.error('ValueAsVariableIncludeProcessor: Could not find inline macro extension for '\
                               "'#{call}'.")
          # increase counter, as error occured and no sub call is being processed
          @report.next_step
        else
          @report.logger.debug('ValueAsVariableIncludeProcessor: Calling sub-method.')
          item = ext.process_method.call(doc, target, attrs)
          if !item.text.to_s.empty?
            result = ":#{attribute}: #{item.text}"
            @report.logger.debug("ValueAsVariableIncludeProcessor: Adding '#{result}' to document.")
            reader.unshift_line(result)
          else
            @report.logger.debug("ValueAsVariableIncludeProcessor: Not adding variable '#{attribute}'"\
                                 ' as query result was empty.')
          end
        end

        reader
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module ERB
    # This class builds a demo report for ERB templates
    class DemoReportBuilder
      # This method is called if a demo report shall be built for the given {Grafana::Panel}.
      # @param panel [Grafana::Panel] panel object, for which a demo entry shall be created.
      # @return [String] String containing the entry, or nil if not possible for given panel
      def build_demo_entry(panel)
        return nil unless panel
        return nil unless panel.model['type'].include?('table')

        ref_id = nil
        panel.model['targets'].each do |item|
          if !item['hide'] && !panel.query(item['refId']).to_s.empty?
            ref_id = item['refId']
            break
          end
        end
        return nil unless ref_id

        <<~DEMO_ERB_TEMPLATE
          <%
          dashboard = '#{panel.dashboard.id}'
          instance = 'default'
          # load the panel object from grafana instance
          panel = @report.grafana(instance).dashboard(dashboard).panel(#{panel.id})
          # build a complete attributes hash, including the variables set for this report call
          # e.g. including command line parameters etc.
          attrs = @attributes.merge({ 'result_type' => 'panel_table', 'query' => '#{ref_id}' })
          query = QueryValueQuery.new(panel, variables: attrs)
          %>

          This is a test table for panel <%= panel.id %>:

          <%= query.execute %>

          For detailed API documentation you may start with:
            1) the AbstractReport (https://rubydoc.info/gems/ruby-grafana-reporter/GrafanaReporter/AbstractReport), or
            2) subclasses of the AbstractQuery (https://rubydoc.info/gems/ruby-grafana-reporter/GrafanaReporter/AbstractQuery)
        DEMO_ERB_TEMPLATE
      end
    end
  end
end

# frozen_string_literal: true

require 'erb'

module GrafanaReporter
  module ERB
    # Implementation of a specific {AbstractReport}. It is used to
    # build reports specifically for erb templates.
    class Report < ::GrafanaReporter::AbstractReport
      # Starts to create an asciidoctor report. It utilizes all extensions in the {GrafanaReporter::Asciidoctor}
      # namespace to realize the conversion.
      # @see AbstractReport#build
      def build
        attrs = @config.default_document_attributes.merge(@custom_attributes).merge({ 'grafana_report_timestamp' => ::Grafana::Variable.new(Time.now.to_s) })
        logger.debug("Document attributes: #{attrs}")

        File.write(path, ::ERB.new(File.read(@template)).result(ReportJail.new(self, attrs).bind))
      end

      # @see AbstractReport#default_template_extension
      def self.default_template_extension
        'erb'
      end

      # @see AbstractReport#default_result_extension
      def self.default_result_extension
        'txt'
      end

      # @see AbstractReport#demo_report_classes
      def self.demo_report_classes
        [DemoReportBuilder]
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module ERB
    # An instance of this class is used as binding for the ERB execution, i.e.
    # this class contains everything known within the ERB template
    class ReportJail
      attr_reader :report, :attributes

      def initialize(report, attributes)
        @report = report
        @attributes = attributes
      end

      # @return binding to this object
      def bind
        binding
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  # This module contains all classes, which are used by the grafana reporter
  # application. The application is a set of classes, which allows to run the
  # reporter in several ways.
  #
  # If you intend to use the reporter functionality, without the application,
  # it might be helpful to not use the classes from here.
  module Application
    # This class contains the main application to run the grafana reporter.
    #
    # It can be run to test the grafana connection, render a single template
    # or run as a service.
    class Application
      # Contains the {Configuration} object of the application.
      attr_accessor :config

      # Stores the {Webservice} object of the application
      attr_reader :webservice

      def initialize
        @config = Configuration.new
        @webservice = Webservice.new
      end

      # This is the main method, which is called, if the application is
      # run in standalone mode.
      # @param params [Array<String>] command line parameters, mainly ARGV can be used.
      # @return [Integer] 0 if everything is fine, -1 if execution aborted.
      def configure_and_run(params = [])
        config_file = Configuration::DEFAULT_CONFIG_FILE_NAME
        tmp_config = Configuration.new
        action_wizard = false

        parser = OptionParser.new do |opts|
          opts.banner = if ENV['OCRAN_EXECUTABLE']
                          "Usage: #{ENV['OCRAN_EXECUTABLE'].gsub("#{Dir.pwd}/".gsub('/', '\\'), '')} [options]"
                        else
                          "Usage: #{Gem.ruby} #{$PROGRAM_NAME} [options]"
                        end

          opts.on('-c', '--config CONFIG_FILE_NAME', 'Specify custom configuration file,'\
                  " instead of #{Configuration::DEFAULT_CONFIG_FILE_NAME}.") do |file_name|
            config_file = file_name
          end

          opts.on('-r', '--register FILE', 'Register a custom plugin, e.g. your own Datasource implementation') do |plugin|
            require plugin
          end

          opts.on('-d', '--debug LEVEL', 'Specify detail level: FATAL, ERROR, WARN, INFO, DEBUG.') do |level|
            tmp_config.set_param('grafana-reporter:debug-level', level)
          end

          opts.on('-o', '--output FILE', 'Output filename if only a single file is rendered') do |file|
            tmp_config.set_param('to_file', file)
          end

          opts.on('-s', '--set VARIABLE,VALUE', Array, 'Set a variable value, which will be passed to the '\
                  'rendering') do |list|
            raise ParameterValueError, list.length unless list.length == 2

            tmp_config.set_param("default-document-attributes:#{list[0]}", list[1])
          end

          opts.on('--ssl-cert FILE', 'Manually specify a SSL cert file for HTTPS connection to grafana. Only '\
                  'needed if not working properly otherwise.') do |file|
            if File.file?(file)
              tmp_config.set_param('grafana-reporter:ssl-cert', file)
            else
              config.logger.warn("SSL certificate file #{file} does not exist. Setting will be ignored.")
            end
          end

          opts.on('--test GRAFANA_INSTANCE', 'test current configuration against given GRAFANA_INSTANCE') do |instance|
            tmp_config.set_param('grafana-reporter:run-mode', 'test')
            tmp_config.set_param('grafana-reporter:test-instance', instance)
          end

          opts.on('-t', '--template TEMPLATE', 'Render a single ASCIIDOC template to PDF and exit') do |template|
            tmp_config.set_param('grafana-reporter:run-mode', 'single-render')
            tmp_config.set_param('default-document-attributes:var-template', template)
          end

          opts.on('-w', '--wizard', 'Configuration wizard to prepare environment for the reporter.') do
            action_wizard = true
          end

          opts.on('-v', '--version', 'Version information') do
            puts GRAFANA_REPORTER_VERSION.join('.')
            return -1
          end

          opts.on('-h', '--help', 'Show this message') do
            puts opts
            return -1
          end
        end

        begin
          parser.parse!(params)
          return ConsoleConfigurationWizard.new.start_wizard(config_file, tmp_config) if action_wizard
        rescue ApplicationError => e
          puts e.message
          return -1
        end

        # abort if config file does not exist
        unless File.file?(config_file)
          puts "Config file '#{config_file}' does not exist. Consider calling the configuration wizard"\
               ' with option \'-w\' or use \'-h\' to see help message. Aborting.'
          return -1
        end

        # merge command line configuration with read config file
        @config.load_config_from_file(config_file)
        @config.merge!(tmp_config)

        run
      end

      # Runs the application with the current set {Configuration} object.
      # @return [Integer] value smaller than 0, if error. 0 if successfull
      def run
        begin
          config.validate
        rescue ConfigurationError => e
          puts e.message
          return -2
        end

        case config.mode
        when Configuration::MODE_CONNECTION_TEST
          res = Grafana::Grafana.new(config.grafana_host(config.test_instance),
                                     config.grafana_api_key(config.test_instance),
                                     logger: config.logger).test_connection
          puts res

        when Configuration::MODE_SINGLE_RENDER
          begin
            template_ext = config.report_class.default_template_extension
            report_ext = config.report_class.default_result_extension
            default_to_file = File.basename(config.template.to_s.gsub(/(?:\.#{template_ext})?$/, ".#{report_ext}"))

            to_file = config.to_file
            to_file = "#{config.reports_folder}#{default_to_file}" if to_file == true
            config.report_class.new(config).create_report(config.template, to_file)
          rescue StandardError => e
            puts "#{e.message}\n#{e.backtrace.join("\n")}"
          end

        when Configuration::MODE_SERVICE
          @webservice.run(config)
        end

        0
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Application
    # General grafana application error, from which the specific errors
    # inherit.
    class ApplicationError < GrafanaReporterError
    end

    # Thrown, if the '-s' parameter is not configured with exactly one variable
    # name and one value.
    class ParameterValueError < ApplicationError
      def initialize(length)
        super("Parameter '-s' needs exactly two values separated by comma, received #{length}.")
      end
    end

    # Thrown, if a webservice request has been requested, which could not be
    # handled.
    class WebserviceUnknownPathError < ApplicationError
      def initialize(request)
        super("Request '#{request}' calls an unknown path for this webservice.")
      end
    end

    # Thrown, if an internal error appeared during creation of the report.
    class WebserviceGeneralRenderingError < ApplicationError
      def initialize(error)
        super("Could not render report because of internal error: #{error}")
      end
    end
  end
end

# frozen_string_literal: true

module GrafanaReporter
  module Application
    # This class provides the webservice for the reporter application. It does not
    # make use of `webrick` or similar, so that it can be used without futher dependencies
    # in conjunction with the standard asciidoctor docker container.
    class Webservice
      # Array of possible webservice running states
      STATUS = %I[stopped running stopping].freeze

      def initialize
        @reports = []
        @status = :stopped
      end

      # Runs the webservice with the given {Configuration} object.
      def run(config)
        @config = config
        @logger = config.logger

        # start webserver
        @server = TCPServer.new(@config.webserver_port)
        @logger.info("Server listening on port #{@config.webserver_port}...")

        @progress_reporter = Thread.new {}

        @status = :running
        begin
          accept_requests_loop
        rescue SystemExit, Interrupt
          @logger.info("Server shutting down.")
          stop!
          retry
        end
        @status = :stopped
      end

      # @return True, if webservice is stopped, false otherwise
      def stopped?
        @status == :stopped
      end

      # @return True, if webservice is up and running, false otherwise
      def running?
        @status == :running
      end

      # Forces stopping the webservice.
      def stop!
        @status = :stopping

        # invoke a new request, so that the webservice stops.
        socket = TCPSocket.new('localhost', @config.webserver_port)
        socket.send '', 0
        socket.close
      end

      private

      def accept_requests_loop
        loop do
          # step 1) accept incoming connection
          socket = @server.accept

          # stop webservice properly, if shall be shutdown
          if @status == :stopping
            socket.close
            break
          end

          # step 2) print the request headers (separated by a blank line e.g. \r\n)
          request = ''
          line = ''
          begin
            until line == "\r\n"
              line = socket.readline
              request += line
            end
          rescue EOFError => e
            @logger.debug("Webserver EOFError: #{e.message}")
          end

          begin
            response = handle_request(request)
            socket.write response
          rescue WebserviceUnknownPathError => e
            @logger.debug(e.message)
            socket.write http_response(404, '', e.message)
          rescue WebserviceGeneralRenderingError => e
            @logger.error(e.message)
            socket.write http_response(400, 'Bad Request', e.message)
          rescue StandardError => e
            @logger.fatal("#{e.message}\n#{e.backtrace.join("\n")}")
            socket.write http_response(400, 'Bad Request', "#{e.message}\n#{e.backtrace.join("\n")}")
          ensure
            socket.close
          end

          log_report_progress
          clean_outdated_temporary_reports
        end
      end

      def log_report_progress
        return if @progress_reporter.alive?

        @progress_reporter = Thread.new do
          running_reports = @reports.reject(&:done)
          until running_reports.empty?
            unless running_reports.empty?
              @logger.info("#{running_reports.length} report(s) in progress: "\
                           "#{running_reports.map do |report|
                                "#{(report.progress * 100).to_i}% (running #{report.execution_time.to_i} secs)"
                              end.join(', ')}")
            end
            sleep 5
            running_reports = @reports.reject(&:done)
          end
          # puts "no more running reports - stopping to report progress"
        end
      end

      def clean_outdated_temporary_reports
        clean_time = Time.now - 60 * 60 * @config.report_retention
        @reports.select { |report| report.done && clean_time > report.end_time }.each do |report|
          @reports.delete(report).delete_file
        end
      end

      def handle_request(request)
        raise WebserviceUnknownPathError, request.split("\r\n")[0] if request.nil?
        raise WebserviceUnknownPathError, request.split("\r\n")[0] if request.split("\r\n")[0].nil?

        query_string = request.split("\r\n")[0].gsub(%r{(?:[^?]+\?)(.*)(?: HTTP/.*)$}, '\1')
        query_parameters = CGI.parse(query_string)

        @logger.debug("Received request: #{request.split("\r\n")[0]}")
        @logger.debug("query_parameters: #{query_parameters}")

        # read URL parameters
        attrs = {}
        query_parameters.each do |k, v|
          attrs[k] = v.length == 1 ? v[0] : v
        end

        case request.split("\r\n")[0]
        when %r{^GET /render[? ]}
          return render_report(attrs)

        when %r{^GET /overview[? ]}
          # show overview for current reports
          return get_reports_status_as_html(@reports)

        when %r{^GET /view_report[? ]}
          return view_report(attrs)

        when %r{^GET /cancel_report[? ]}
          return cancel_report(attrs)

        when %r{^GET /view_log[? ]}
          return view_log(attrs)
        end

        raise WebserviceUnknownPathError, request.split("\r\n")[0]
      end

      def view_log(attrs)
        # view report if already available, or show status view
        report = @reports.select { |r| r.object_id.to_s == attrs['report_id'].to_s }.first
        raise WebserviceGeneralRenderingError, 'view_log has been called without valid id' if report.nil?

        content = report.full_log

        http_response(200, 'OK', content, "Content-Type": 'text/plain')
      end

      def cancel_report(attrs)
        # view report if already available, or show status view
        report = @reports.select { |r| r.object_id.to_s == attrs['report_id'].to_s }.first
        raise WebserviceGeneralRenderingError, 'cancel_report has been called without valid id' if report.nil?

        report.cancel! unless report.done

        # redirect to view_report page
        http_response(302, 'Found', nil, Location: "/view_report?report_id=#{report.object_id}")
      end

      def view_report(attrs)
        # view report if already available, or show status view
        report = @reports.select { |r| r.object_id.to_s == attrs['report_id'].to_s }.first
        raise WebserviceGeneralRenderingError, 'view_report has been called without valid id' if report.nil?

        # show report status
        return get_reports_status_as_html([report]) if !report.done || !report.error.empty?

        # provide report
        @logger.debug("Returning PDF report at #{report.path}")
        content = File.read(report.path, mode: 'rb')
        return http_response(200, 'OK', content, "Content-Type": 'application/pdf') if content.start_with?('%PDF')

        http_response(200, 'OK', content, "Content-Type": 'application/octet-stream',
                                          "Content-Disposition": 'attachment; '\
                                                                 "filename=report_#{attrs['report_id']}.zip")
      end

      def render_report(attrs)
        # build report
        template_file = "#{@config.templates_folder}#{attrs['var-template']}"

        file = Tempfile.new('gf_pdf_', @config.reports_folder)
        begin
          FileUtils.chmod('+r', file.path)
        rescue StandardError => e
          @logger.debug("File permissions could not be set for #{file.path}: #{e.message}")
        end

        report = @config.report_class.new(@config)
        Thread.report_on_exception = false
        Thread.new do
          report.create_report(template_file, file, attrs)
        end
        @reports << report

        http_response(302, 'Found', nil, Location: "/view_report?report_id=#{report.object_id}")
      end

      def get_reports_status_as_html(reports)
        i = reports.length

        # TODO: make reporter HTML results customizable
        template = <<~HTML_TEMPLATE
          <html>
          <head></head>
          <body>
          <table>
            <thead>
              <th>#</th><th>Start Time</th><th>End Time</th><th>Template</th><th>Execution time</th>
              <th>Status</th><th>Error</th><th>Action</th>
            </thead>
            <tbody>
            <% reports.reverse.map do |report| %>
              <tr><td><%= i-= 1 %></td><td><%= report.start_time %></td><td><%= report.end_time %></td>
              <td><%= report.template %></td><td><%= report.execution_time.to_i %> secs</td>
              <td><%= report.status %> (<%= (report.progress * 100).to_i %>%)</td>
              <td><%= report.error.join('<br>') %></td>
              <td><% if !report.done && !report.cancel %>
                <a href="/cancel_report?report_id=<%= report.object_id %>">Cancel</a>
              <% end %>
              &nbsp;
              <% if (report.status == 'finished') || (report.status == 'cancelled') %>
                <a href="/view_report?report_id=<%= report.object_id %>">View</a>
              <% end %>
              &nbsp;
              <a href="/view_log?report_id=<%= report.object_id %>">Log</a></td></tr>
            <% end.join('') %>
            <tbody>
          </table>
          <p style="font-size: small; color:grey">You are running ruby-grafana-reporter version <%= GRAFANA_REPORTER_VERSION.join('.') %>.<%= @config.latest_version_check_ok? ? '' : ' Check out the latest version <a href="https://github.com/divinity666/ruby-grafana-reporter/releases/latest">here</a>.' %></p>
          </body>
          </html>
        HTML_TEMPLATE

        content = ::ERB.new(template).result(binding)

        http_response(200, 'OK', content, "Content-Type": 'text/html')
      end

      def http_response(code, text, body, opts = {})
        "HTTP/1.1 #{code} #{text}\r\n#{opts.map { |k, v| "#{k}: #{v}" }.join("\r\n")}"\
        "#{body ? "\r\nContent-Length: #{body.to_s.bytesize}" : ''}\r\n\r\n#{body}"
      end
    end
  end
end


GrafanaReporter::Application::Application.new.configure_and_run(ARGV)